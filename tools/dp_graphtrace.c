#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <rte_eal.h>
#include <rte_alarm.h>
#include <getopt.h>

#include "dp_error.h"
#include "dp_log.h"
#include "monitoring/dp_graphtrace_shared.h"
#include "rte_flow/dp_rte_flow.h"

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
	"dp_graphtrace",				// this binary (not used, can actually be any string)
	"--proc-type=secondary",		// connect to the primary process (dp_service) instead
	"--no-pci",						// do not try to use any hardware
	"--log-level=6",				// hide DPDK's informational messages (level 7)
};

enum cmd_opt_type {
	DP_GRAPHTRACE_OPT_MIN = 256,
	DP_GRAPHTRACE_OPT_HELP,
	DP_GRAPHTRACE_OPT_CAPTURE_HW_PKT,
};

static bool capture_hw_pkt = false;

#define OPTSTRING \
	"h" /* help */

static const struct option longopts[] = {
	{ "help", 0, 0, DP_GRAPHTRACE_OPT_HELP },
	{ "hw-packet", 0, 0, DP_GRAPHTRACE_OPT_CAPTURE_HW_PKT },
	{ NULL, 0, 0, 0 },
};


static char *eal_args_mem[RTE_DIM(eal_arg_strings)];
static char *eal_args[RTE_DIM(eal_args_mem)];

static bool interrupt = false;
static bool primary_alive = false;

static int eal_init(void)
{
	for (uint i = 0; i < RTE_DIM(eal_arg_strings); ++i) {
		eal_args[i] = eal_args_mem[i] = strdup(eal_arg_strings[i]);
		if (!eal_args[i]) {
			fprintf(stderr, "Cannot allocate EAL arguments\n");
			for (uint j = 0; j < RTE_DIM(eal_args_mem); ++j)
				free(eal_args_mem[j]);
			return DP_ERROR;
		}
	}
	return rte_eal_init(RTE_DIM(eal_args), eal_args);
}

static void eal_cleanup(void)
{
	rte_eal_cleanup();
	for (uint i = 0; i < RTE_DIM(eal_args_mem); ++i)
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

static void dp_graphtrace_config_start_stop_parameters(struct dp_graphtrace_mp_request *graphtrace_request)
{
	if (capture_hw_pkt)
		graphtrace_request->action_params.op_type = DP_GRAPHTRACE_OP_TYPE_OFFLOAD;
	else
		graphtrace_request->action_params.op_type = DP_GRAPHTRACE_OP_TYPE_SOFTWARE;
}


static int dp_graphtrace_send_request(enum dp_graphtrace_action action, struct dp_graphtrace_mp_reply *reply)
{
	struct rte_mp_msg mp_request;
	struct rte_mp_reply mp_reply;
	struct dp_graphtrace_mp_request *graphtrace_request;
	struct dp_graphtrace_mp_reply *graphtrace_reply;

	rte_strscpy(mp_request.name, DP_MP_ACTION_GRAPHTRACE, sizeof(mp_request.name));
	mp_request.len_param = sizeof(struct dp_graphtrace_mp_request);
	mp_request.num_fds = 0;

	graphtrace_request = (struct dp_graphtrace_mp_request *)mp_request.param;
	graphtrace_request->action = action;

	switch (action) {
	case DP_GRAPHTRACE_ACTION_START:
		dp_graphtrace_config_start_stop_parameters(graphtrace_request);
		break;
	case DP_GRAPHTRACE_ACTION_STOP:
		dp_graphtrace_config_start_stop_parameters(graphtrace_request);
		break;
	}

	if (DP_FAILED(rte_mp_request_sync(&mp_request, &mp_reply, &connect_timeout))) {
		fprintf(stderr, "Cannot request graphtrace %s\n", dp_strerror_verbose(rte_errno));
		return -rte_errno;
	}

	graphtrace_reply = (struct dp_graphtrace_mp_reply *)mp_reply.msgs[0].param;
	rte_memcpy(reply, graphtrace_reply, sizeof(struct dp_graphtrace_mp_reply));

	free(mp_reply.msgs);

	return DP_OK;
}

static void print_packet(struct rte_mbuf *pkt)
{
	char printbuf[512];
	struct dp_graphtrace_pktinfo *pktinfo = dp_get_graphtrace_pktinfo(pkt);

	switch (pktinfo->pkt_type) {
	case DP_GRAPHTRACE_PKT_TYPE_SOFTWARE:
		dp_graphtrace_sprint(pkt, printbuf, sizeof(printbuf));
		printf("%u: " NODENAME_FMT " %s " NODENAME_FMT ": %s\n",
			pktinfo->pktid,
			pktinfo->node->name,
			pktinfo->next_node ? "->" : "  ",
			pktinfo->next_node ? pktinfo->next_node->name : "",
			printbuf);
		break;
	case DP_GRAPHTRACE_PKT_TYPE_OFFLOAD:
		printf("%u: " NODENAME_FMT "    " NODENAME_FMT ": %s\n",
			pktinfo->pktid,
			"Offloaded", "",
			printbuf);
		break;
	}
}

static int dp_graphtrace_dump(struct dp_graphtrace *graphtrace)
{
	uint received, available;
	void *objs[DP_GRAPHTRACE_RINGBUF_SIZE];

	// dump what's already in the ring buffer
	// (when full, it actually prevents new packets to enter, thus containing only stale ones)
	received = rte_ring_dequeue_burst(graphtrace->ringbuf, objs, RTE_DIM(objs), &available);
	if (received > 0)
		rte_mempool_put_bulk(graphtrace->mempool, objs, received);

	while (!interrupt) {
		received = rte_ring_dequeue_burst(graphtrace->ringbuf, objs, RTE_DIM(objs), &available);
		if (received > 0) {
			for (uint i = 0; i < received; ++i)
				print_packet((struct rte_mbuf *)objs[i]);
			rte_mempool_put_bulk(graphtrace->mempool, objs, received);
		}
		if (available == 0)
			usleep(WAIT_INTERVAL);
	}

	return DP_OK;
}

static int dp_graphtrace_request(enum dp_graphtrace_action action, struct dp_graphtrace_mp_reply *reply)
{
	int ret;

	ret = dp_graphtrace_send_request(action, reply);
	if (DP_FAILED(ret)) {
		fprintf(stderr, "Cannot send graphtrace request, action=%d %s\n", action, dp_strerror_verbose(ret));
		return ret;
	}

	if (DP_FAILED(reply->error_code)) {
		fprintf(stderr, "Graphtrace action request failed, action=%d %s\n", action, dp_strerror_verbose(reply->error_code));
		return DP_ERROR;
	}

	return DP_OK;
}

static int dp_graphtrace_start(void)
{
	int ret;
	struct dp_graphtrace_mp_reply reply;

	ret = dp_graphtrace_request(DP_GRAPHTRACE_ACTION_START, &reply);
	if (DP_FAILED(ret))
		return ret;

	primary_alive = true;
	return DP_OK;

}

static int dp_graphtrace_stop(void)
{
	struct dp_graphtrace_mp_reply reply;

	if (!primary_alive)
		return DP_OK;

	return dp_graphtrace_request(DP_GRAPHTRACE_ACTION_STOP, &reply);
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

static int do_graphtrace(struct dp_graphtrace *graphtrace)
{
	int ret;

	if (DP_FAILED(dp_graphtrace_connect(graphtrace))) {
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

	ret = dp_graphtrace_dump(graphtrace);

	if (DP_FAILED(dp_graphtrace_stop())) {
		fprintf(stderr, "Failed to request graph tracing termination\n");
		ret = DP_ERROR;
	}

	rte_eal_alarm_cancel(dp_graphtrace_monitor_primary, (void *)-1);

	return ret;
}

static void signal_handler(__rte_unused int signum)
{
	interrupt = true;
}

static void dp_print_usage(const char *prgname)
{
	fprintf(stderr,
		"%s: dp-service graph-tracing utility\n"
		" --help                show this help message and exit\n"
		" --hw-packet           capture pkts after offloading rules are installed (experimental feature, only VF's outgoing packets are supported)\n",
		prgname);
}

static int parse_args(int argc, char **argv)
{
	int opt;
	char *prgname = argv[0];

	while ((opt = getopt_long(argc, argv, OPTSTRING, longopts, NULL)) != -1) {
		switch (opt) {
		case 'h':
		case DP_GRAPHTRACE_OPT_HELP:
			dp_print_usage(prgname);
			return DP_CONF_RUNMODE_EXIT;
		case DP_GRAPHTRACE_OPT_CAPTURE_HW_PKT:
			capture_hw_pkt = true;
			break;
		default:
			dp_print_usage(prgname);
			return DP_CONF_RUNMODE_ERROR;
		}
	}

	return DP_CONF_RUNMODE_NORMAL;
}

int main(int argc, char **argv)
{
	struct dp_graphtrace graphtrace;
	int retcode;
	int ret;

	ret = parse_args(argc, argv);
	switch (ret) {
	case DP_CONF_RUNMODE_ERROR:
		fprintf(stderr, "Cannot parse command-line options %s\n", dp_strerror_verbose(ret));
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

	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	retcode = DP_FAILED(do_graphtrace(&graphtrace)) ? EXIT_FAILURE : EXIT_SUCCESS;

	eal_cleanup();

	return retcode;
}
