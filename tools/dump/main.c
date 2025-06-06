// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#include <fcntl.h>
#include <getopt.h>
#include <regex.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <rte_alarm.h>

#include "dp_error.h"
#include "dp_log.h"
#include "dp_version.h"
#include "monitoring/dp_graphtrace_shared.h"
#include "monitoring/dp_pcap.h"
#include "rte_flow/dp_rte_flow.h"
#include "../common/dp_secondary_eal.h"

// generated definitions for getopt(),
// generated storage variables and
// generated getters for such variables
#include "opts.h"
#include "opts.c"

// longest node name is 'overlay-switch'
#define NODENAME_FMT "%-14s"

// check if primary process is alive every N microseconds
#define MONITOR_INTERVAL (500 * 1000)
// when the packet buffer is empty, wait for N microseconds (unlikely in production)
#define WAIT_INTERVAL (100 * 1000)

static const struct timespec connect_timeout = {
	.tv_sec = 2,
	.tv_nsec = 0,
};

static const char *pcap_path = NULL;
static struct dp_pcap dp_pcap;

static bool showing_nodes = false;
static char node_filter[DP_GRAPHTRACE_NODE_REGEX_MAXLEN] = "";
static char packet_filter[DP_GRAPHTRACE_FILTER_MAXLEN] = "";

static bool interrupt = false;
static bool primary_alive = false;

// optimization to prevent 'if (pcap) pcap_dump(); else print_packet();' in a loop
static void print_packet(struct dp_pcap *dp_pcap, struct rte_mbuf *m, struct timeval *timestamp);
static void (*dump_func)(struct dp_pcap *dp_pcap, struct rte_mbuf *m, struct timeval *timestamp) = print_packet;


static int dp_graphtrace_connect(struct dp_graphtrace *graphtrace)
{
	graphtrace->mempool = rte_mempool_lookup(DP_GRAPHTRACE_MEMPOOL_NAME);
	if (!graphtrace->mempool)
		return DP_ERROR;

	graphtrace->ringbuf = rte_ring_lookup(DP_GRAPHTRACE_RINGBUF_NAME);
	if (!graphtrace->ringbuf)
		return DP_ERROR;

	graphtrace->filters = rte_memzone_lookup(DP_GRAPHTRACE_FILTERS_NAME);
	if (!graphtrace->filters)
		return DP_ERROR;

	return DP_OK;
}

static void print_packet(__rte_unused struct dp_pcap *context, struct rte_mbuf *pkt, struct timeval *timestamp)
{
	struct dp_graphtrace_pktinfo *pktinfo = dp_get_graphtrace_pktinfo(pkt);
	struct tm *tm;
	char printbuf[512];
	char node_buf[16];
	char next_node_buf[16];
	const char *node;
	const char *next_node;
	const char *arrow;

	dp_graphtrace_sprint(pkt, printbuf, sizeof(printbuf));

	arrow = "->";
	if (pktinfo->node) {
		node = pktinfo->node->name;
	} else {
		arrow = ">>";
		snprintf(node_buf, sizeof(node_buf), "PORT %u", pkt->port);
		node = node_buf;
	}
	if (pktinfo->next_node) {
		next_node = pktinfo->next_node->name;
	} else {
		arrow = ">>";
		if (pktinfo->dst_port_id == (uint16_t)-1) {
			next_node = "DROP";
		} else {
			snprintf(next_node_buf, sizeof(next_node_buf), "PORT %u", pktinfo->dst_port_id);
			next_node = next_node_buf;
		}
	}

	tm = gmtime(&timestamp->tv_sec);
	printf("%02d:%02d:%02d.%03d %u: " NODENAME_FMT " %s " NODENAME_FMT ": %s\n",
		   tm->tm_hour, tm->tm_min, tm->tm_sec, (int)(timestamp->tv_usec/1000),
		   pktinfo->pktid, node, arrow, next_node, printbuf);

	fflush(stdout);
}

static int dp_graphtrace_dump(struct dp_graphtrace *graphtrace)
{
	unsigned int received, available;
	void *objs[DP_GRAPHTRACE_RINGBUF_SIZE];
	struct timeval timestamp;

	// dump what's already in the ring buffer
	// (when full, it actually prevents new packets to enter, thus containing only stale ones)
	received = rte_ring_dequeue_burst(graphtrace->ringbuf, objs, RTE_DIM(objs), &available);
	if (received > 0)
		rte_mempool_put_bulk(graphtrace->mempool, objs, received);

	while (!interrupt) {
		received = rte_ring_dequeue_burst(graphtrace->ringbuf, objs, RTE_DIM(objs), &available);
		if (received > 0) {
			// TODO timestamp should be sent by dpservice
			// ignoring failure for speed
			gettimeofday(&timestamp, NULL);
			for (unsigned int i = 0; i < received; ++i)
				dump_func(&dp_pcap, (struct rte_mbuf *)objs[i], &timestamp);
			rte_mempool_put_bulk(graphtrace->mempool, objs, received);
		}
		if (available == 0)
			usleep(WAIT_INTERVAL);
	}

	return DP_OK;
}

static int dp_graphtrace_request(struct dp_graphtrace_mp_request *request, struct dp_graphtrace_mp_reply *reply)
{
	struct rte_mp_msg mp_request;
	struct rte_mp_reply mp_reply;

	static_assert(sizeof(struct dp_graphtrace_mp_request) <= sizeof(mp_request.param),
				  "Graphtrace request is too big");

	rte_strscpy(mp_request.name, DP_MP_ACTION_GRAPHTRACE, sizeof(mp_request.name));
	mp_request.len_param = sizeof(struct dp_graphtrace_mp_request);
	mp_request.num_fds = 0;

	*((struct dp_graphtrace_mp_request *)mp_request.param) = *request;

	if (DP_FAILED(rte_mp_request_sync(&mp_request, &mp_reply, &connect_timeout))) {
		fprintf(stderr, "Cannot send graphtrace request, action=%d %s\n", request->action, dp_strerror_verbose(rte_errno));
		return DP_ERROR;
	}

	*reply = *((struct dp_graphtrace_mp_reply *)mp_reply.msgs[0].param);

	free(mp_reply.msgs);

	if (DP_FAILED(reply->error_code)) {
		fprintf(stderr, "Graphtrace request failed, action=%d %s\n", request->action, dp_strerror_verbose(reply->error_code));
		return DP_ERROR;
	}

	return DP_OK;
}

static int dp_graphtrace_start(struct dp_graphtrace *graphtrace)
{
	int ret;
	struct dp_graphtrace_mp_reply reply;
	struct dp_graphtrace_mp_request request = {
		.action = DP_GRAPHTRACE_ACTION_START,
		.params.start.drops = dp_conf_is_showing_drops(),
		.params.start.nodes = showing_nodes,
	};
	struct dp_graphtrace_params *filters = (struct dp_graphtrace_params *)graphtrace->filters->addr;

	// sizes already checked by argument parser, default is an empty string
	snprintf(filters->node_regex, sizeof(filters->node_regex), "%s", node_filter);
	snprintf(filters->filter_string, sizeof(filters->filter_string), "%s", packet_filter);

	ret = dp_graphtrace_request(&request, &reply);
	if (DP_FAILED(ret))
		return ret;

	primary_alive = true;
	return DP_OK;

}

static int dp_graphtrace_stop(void)
{
	struct dp_graphtrace_mp_reply reply;
	struct dp_graphtrace_mp_request request = {
		.action = DP_GRAPHTRACE_ACTION_STOP,
	};

	if (!primary_alive)
		return DP_OK;

	return dp_graphtrace_request(&request, &reply);
}

static void dp_graphtrace_monitor_primary(void *arg __rte_unused)
{
	int ret;

	// Reference code from DPDK's pdump primary process monitor uses atomic operations on the variabls
	// for synchronization. We use direct assignment here as no negative impact is observed so far.

	// already terminating
	if (interrupt)
		return;

	if (!rte_eal_primary_proc_alive(NULL)) {
		fprintf(stderr, "dp-service process is no longer active, terminating...\n");
		primary_alive = false;  // prevent STOP request
		interrupt = true;
		return;
	}

	// re-schedule the alarm for next time
	ret = rte_eal_alarm_set(MONITOR_INTERVAL, dp_graphtrace_monitor_primary, NULL);
	if (DP_FAILED(ret))
		fprintf(stderr, "Warning: Cannot re-schedule primary process monitor %s\n", dp_strerror_verbose(ret));
}

static void signal_handler(__rte_unused int signum)
{
	interrupt = true;
}

static int dp_graphtrace_main(void)
{
	struct dp_graphtrace graphtrace;
	int ret;

	if (signal(SIGINT, signal_handler) == SIG_ERR
		|| signal(SIGTERM, signal_handler) == SIG_ERR
		|| signal(SIGPIPE, signal_handler) == SIG_ERR
	) {
		fprintf(stderr, "Cannot setup essential signal handlers %s\n", dp_strerror_verbose(errno));
		return DP_ERROR;
	}

	if (DP_FAILED(dp_graphtrace_connect(&graphtrace))) {
		fprintf(stderr, "Cannot connect to service\n");
		return DP_ERROR;
	}

	// stop this client when primary exits
	ret = rte_eal_alarm_set(MONITOR_INTERVAL, dp_graphtrace_monitor_primary, NULL);
	if (DP_FAILED(ret)) {
		fprintf(stderr, "Cannot enable service liveness monitor %s\n", dp_strerror_verbose(ret));
		return ret;
	}

	if (DP_FAILED(dp_graphtrace_start(&graphtrace))) {
		fprintf(stderr, "Failed to request graph tracing\n");
		rte_eal_alarm_cancel(dp_graphtrace_monitor_primary, (void *)-1);
		return DP_ERROR;
	}

	ret = dp_graphtrace_dump(&graphtrace);

	if (DP_FAILED(dp_graphtrace_stop())) {
		fprintf(stderr, "Failed to request graph tracing termination\n");
		ret = DP_ERROR;
	} else
		fprintf(stderr, "\nGraphtrace successfully disabled in dp-service\n");

	rte_eal_alarm_cancel(dp_graphtrace_monitor_primary, (void *)-1);

	return ret;
}

static int do_graphtrace(void)
{
	int ret;

	if (pcap_path) {
		ret = dp_pcap_init(&dp_pcap, pcap_path);
		if (DP_FAILED(ret)) {
			fprintf(stderr, "Cannot initialize pcap: %s %s\n", dp_pcap.error,
					ret == DP_ERROR ? "" : dp_strerror_verbose(ret));
			return ret;
		}
	}

	ret = dp_graphtrace_main();

	if (pcap_path)
		dp_pcap_free(&dp_pcap);

	return ret;
}

static int stop_graphtrace(void)
{
	// without this, nothing gets sent
	primary_alive = true;

	if (DP_FAILED(dp_graphtrace_stop())) {
		fprintf(stderr, "Failed to request graph tracing termination\n");
		return DP_ERROR;
	}
	return DP_OK;
}

static void dp_argparse_version(void)
{
	printf("DP Service version %s\n", DP_SERVICE_VERSION);
}

static int dp_argparse_opt_pcap(const char *arg)
{
	pcap_path = arg;
	dump_func = dp_pcap_dump;
	return DP_OK;
}

static int dp_argparse_opt_nodes(const char *arg)
{
	regex_t validation_re;
	char reg_error[256];
	int reg_ret;

	// prevent accidental '--nodes -option' meaning '--nodes="-option"'
	if (*arg == '-') {
		fprintf(stderr, "Node filter regular expression starts with ambiguous '-'\n");
		return DP_ERROR;
	}

	if ((size_t)snprintf(node_filter, sizeof(node_filter), "%s", arg) >= sizeof(node_filter)) {
		fprintf(stderr, "Node filter regular expression is too long\n");
		return DP_ERROR;
	}

	reg_ret = regcomp(&validation_re, node_filter, REG_NOSUB);
	if (reg_ret != 0) {
		regerror(reg_ret, &validation_re, reg_error, sizeof(reg_error));
		fprintf(stderr, "Invalid node filter regular expression: %s\n", reg_error);
		return DP_ERROR;
	}

	regfree(&validation_re);

	showing_nodes = true;
	return DP_OK;
}

static int dp_argparse_opt_filter(const char *arg)
{
	struct bpf_program validation_bpf;

	if ((size_t)snprintf(packet_filter, sizeof(packet_filter), "%s", arg) >= sizeof(packet_filter)) {
		fprintf(stderr, "Filter string is too long\n");
		return DP_ERROR;
	}

	if (DP_FAILED(dp_compile_bpf(&validation_bpf, arg))) {
		fprintf(stderr, "Invalid Filter string\n");
		return DP_ERROR;
	}

	dp_free_bpf(&validation_bpf);

	return DP_OK;
}


int main(int argc, char **argv)
{
	const char *file_prefix;
	int ret;

	switch (dp_conf_parse_args(argc, argv)) {
	case DP_CONF_RUNMODE_ERROR:
		return EXIT_FAILURE;
	case DP_CONF_RUNMODE_EXIT:
		return EXIT_SUCCESS;
	case DP_CONF_RUNMODE_NORMAL:
		break;
	}

	file_prefix = dp_conf_get_eal_file_prefix();
	if (!*file_prefix)
		file_prefix = getenv("DP_FILE_PREFIX");

	ret = dp_secondary_eal_init(file_prefix);
	if (DP_FAILED(ret)) {
		fprintf(stderr, "Cannot init EAL %s\n", dp_strerror_verbose(ret));
		return EXIT_FAILURE;
	}

	if (dp_conf_is_stop_mode())
		ret = stop_graphtrace();
	else
		ret = do_graphtrace();

	dp_secondary_eal_cleanup();

	return DP_FAILED(ret) ? EXIT_FAILURE : EXIT_SUCCESS;
}
