#include <fcntl.h>
#include <getopt.h>
#include <pcap/pcap.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <rte_eal.h>
#include <rte_alarm.h>

#include "dp_error.h"
#include "dp_log.h"
#include "dp_version.h"
#include "monitoring/dp_graphtrace_shared.h"
#include "monitoring/dp_pcap.h"
#include "rte_flow/dp_rte_flow.h"

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

// EAL needs writable arguments (both the string and the array!)
// therefore convert them from literals and remember them for freeing later
static const char *eal_arg_strings[] = {
	"dpservice-dump",				// this binary (not used, can actually be any string)
	"--proc-type=secondary",		// connect to the primary process (dp_service) instead
	"--no-pci",						// do not try to use any hardware
	"--log-level=6",				// hide DPDK's informational messages (level 7)
};

static char *eal_args_mem[RTE_DIM(eal_arg_strings)];
static char *eal_args[RTE_DIM(eal_args_mem)];

static const char *pcap_path = NULL;
static struct dp_pcap dp_pcap;

static bool interrupt = false;
static bool primary_alive = false;

// optimization to prevent 'if (pcap) pcap_dump(); else print_packet();' in a loop
static void print_packet(struct dp_pcap *dp_pcap, struct rte_mbuf *m, struct timeval *timestamp);
static void (*dump_func)(struct dp_pcap *dp_pcap, struct rte_mbuf *m, struct timeval *timestamp) = print_packet;

static int eal_init(void)
{
	for (size_t i = 0; i < RTE_DIM(eal_arg_strings); ++i) {
		eal_args[i] = eal_args_mem[i] = strdup(eal_arg_strings[i]);
		if (!eal_args[i]) {
			fprintf(stderr, "Cannot allocate EAL arguments\n");
			for (size_t j = 0; j < RTE_DIM(eal_args_mem); ++j)
				free(eal_args_mem[j]);
			return DP_ERROR;
		}
	}
	return rte_eal_init(RTE_DIM(eal_args), eal_args);
}

static void eal_cleanup(void)
{
	rte_eal_cleanup();
	for (size_t i = 0; i < RTE_DIM(eal_args_mem); ++i)
		free(eal_args_mem[i]);
}

static int dp_graphtrace_connect(struct dp_graphtrace *graphtrace)
{
	graphtrace->mempool = rte_mempool_lookup(DP_GRAPHTRACE_MEMPOOL_NAME);
	if (!graphtrace->mempool)
		return DP_ERROR;

	graphtrace->ringbuf = rte_ring_lookup(DP_GRAPHTRACE_RINGBUF_NAME);
	if (!graphtrace->ringbuf)
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

	if (pktinfo->pkt_type == DP_GRAPHTRACE_PKT_TYPE_OFFLOAD) {
		snprintf(node_buf, sizeof(node_buf), "PORT %u", pkt->port);
		node = "Offloaded";
		arrow = "at";
		next_node = node_buf;
	} else {
		assert(pktinfo->pkt_type == DP_GRAPHTRACE_PKT_TYPE_SOFTWARE);
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

static int dp_graphtrace_start(void)
{
	int ret;
	struct dp_graphtrace_mp_reply reply;
	struct dp_graphtrace_mp_request request = {
		.action = DP_GRAPHTRACE_ACTION_START,
		.params.start.drops = dp_conf_is_showing_drops(),
		.params.start.nodes = dp_conf_is_showing_nodes(),
		.params.start.hw = dp_conf_is_offload_enabled(),
	};

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

	if (DP_FAILED(dp_graphtrace_start())) {
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

int main(int argc, char **argv)
{
	int ret;

	switch (dp_conf_parse_args(argc, argv)) {
	case DP_CONF_RUNMODE_ERROR:
		return EXIT_FAILURE;
	case DP_CONF_RUNMODE_EXIT:
		return EXIT_SUCCESS;
	case DP_CONF_RUNMODE_NORMAL:
		break;
	}

	ret = eal_init();
	if (DP_FAILED(ret)) {
		fprintf(stderr, "Cannot init EAL %s\n", dp_strerror_verbose(ret));
		return EXIT_FAILURE;
	}

	if (dp_conf_is_stop_mode())
		ret = stop_graphtrace();
	else
		ret = do_graphtrace();

	eal_cleanup();

	return DP_FAILED(ret) ? EXIT_FAILURE : EXIT_SUCCESS;
}
