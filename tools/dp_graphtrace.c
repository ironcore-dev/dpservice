#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <rte_eal.h>
#include <rte_alarm.h>

#include "dp_error.h"
#include "dp_log.h"
#include "monitoring/dp_graphtrace_shared.h"
#include "rte_flow/dp_rte_flow.h"

// longest node name is 'overlay-switch'
#define NODENAME_FMT "%-14s"

#define MONITOR_INTERVAL  (500 * 1000)

// EAL needs writable arguments (both the string and the array!)
// therefore convert them from literals and remember them for freeing later
static const char *eal_arg_strings[] = {
	"dp_graphtrace",				// this binary (not used, can actually be any string)
	"--proc-type=secondary",		// connect to the primary process (dp_service) instead
	"--no-pci",						// do not try to use any hardware
	"--log-level=6",				// hide DPDK's informational messages (level 7)
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

static int dp_graphtrace_send_client_request_sync(uint8_t action, uint8_t dump_type, struct dp_graphtrace_mp_reply *reply)
{
	struct rte_mp_msg mp_request, *mp_reply;
	struct rte_mp_reply mp_reply_raw;
	struct dp_graphtrace_mp_request *request = (struct dp_graphtrace_mp_request *)mp_request.param;
	struct dp_graphtrace_mp_reply *graphtrace_reply;
	struct timespec ts = {.tv_sec = 5, .tv_nsec = 0};

	rte_strscpy(mp_request.name, DP_MP_ACTION_GRAPHTRACE, sizeof(mp_request.name));
	mp_request.len_param = sizeof(struct dp_graphtrace_mp_request);
	mp_request.num_fds = 0;

	request->action = action;
	request->dump_type = dump_type;

	if (rte_mp_request_sync(&mp_request, &mp_reply_raw, &ts) < 0) {
		fprintf(stderr, "Cannot request graphtrace action due to %s \n", dp_strerror_verbose(rte_errno));
		return DP_ERROR;
	}

	mp_reply = &mp_reply_raw.msgs[0];
	graphtrace_reply = (struct dp_graphtrace_mp_reply *)mp_reply->param;
	rte_memcpy(reply, graphtrace_reply, sizeof(struct dp_graphtrace_mp_reply));

	free(mp_reply_raw.msgs);

	return DP_OK;
}

static void print_packet(struct rte_mbuf *pkt)
{
	char printbuf[512];
	struct dp_graphtrace_pktinfo *pktinfo = dp_get_graphtrace_pktinfo(pkt);

	dp_graphtrace_sprint(pkt, printbuf, sizeof(printbuf));
	printf("%u: " NODENAME_FMT " %s " NODENAME_FMT ": %s\n",
		   pktinfo->pktid,
		   pktinfo->node->name,
		   pktinfo->next_node ? "->" : "  ",
		   pktinfo->next_node ? pktinfo->next_node->name : "",
		   printbuf);
}

static int do_graphtrace(struct dp_graphtrace *graphtrace)
{
	uint received, available;
	void *objs[DP_GRAPHTRACE_RINGBUF_SIZE];
	struct dp_graphtrace_mp_reply reply;

	if (DP_FAILED(dp_graphtrace_send_client_request_sync(DP_GRAPHTRACE_ACTION_TYPE_START, 0, &reply))) {
		fprintf(stderr, "Cannot request graphtrace\n");
		return EXIT_FAILURE;
	}

	graphtrace->mempool = reply.mempool;
	graphtrace->ringbuf = reply.ringbuf;

	primary_alive = true;

	// dump what's already in the ring buffer
	// (when full, it actually prevents new packets to enter, thus containing only stale ones)
	received = rte_ring_dequeue_burst(graphtrace->ringbuf, objs, RTE_DIM(objs), &available);
	if (received > 0)
		rte_mempool_put_bulk(graphtrace->mempool, objs, received);

	while (!interrupt && primary_alive) {
		received = rte_ring_dequeue_burst(graphtrace->ringbuf, objs, RTE_DIM(objs), &available);
		if (received > 0) {
			for (uint i = 0; i < received; ++i)
				print_packet((struct rte_mbuf *)objs[i]);
			rte_mempool_put_bulk(graphtrace->mempool, objs, received);
		}
		if (available == 0)
			usleep(100000);
	}

	if (primary_alive) {
		if (DP_FAILED(dp_graphtrace_send_client_request_sync(DP_GRAPHTRACE_ACTION_TYPE_STOP, 0, &reply))) {
			fprintf(stderr, "Cannot request graphtrace\n");
			return EXIT_FAILURE;
		}
	}

	graphtrace->mempool = NULL;
	graphtrace->ringbuf = NULL;


	return EXIT_SUCCESS;
}

static void signal_handler(__rte_unused int signum)
{
	interrupt = true;
}

static void
monitor_primary_process(void *arg __rte_unused)
{

	if (__atomic_load_n(&interrupt, __ATOMIC_RELAXED))
		return;

	if (rte_eal_primary_proc_alive(NULL)) {
		rte_eal_alarm_set(MONITOR_INTERVAL, monitor_primary_process, NULL);
	} else {
		fprintf(stderr,
			"dp-service process is no longer active, dp_graphtrace existing now ...\n");
		__atomic_store_n(&primary_alive, false, __ATOMIC_RELAXED);
		__atomic_store_n(&interrupt, true, __ATOMIC_RELAXED);
	}
}

static int
enable_primary_process_monitor(void)
{
	int ret;

	/* Once primary exits, so will pdump. */
	ret = rte_eal_alarm_set(MONITOR_INTERVAL, monitor_primary_process, NULL);
	if (ret < 0) {
		fprintf(stderr, "Fail to enable monitor:%d\n", ret);
		return ret;
	}

	return DP_OK;
}

int main(void)
{
	struct dp_graphtrace graphtrace;
	int ret;

	ret = eal_init();
	if (DP_FAILED(ret)) {
		fprintf(stderr, "Cannot init EAL %s\n", dp_strerror_verbose(ret));
		return EXIT_FAILURE;
	}

	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	ret = enable_primary_process_monitor();
	if (DP_FAILED(ret)) {
		fprintf(stderr, "Cannot enable primary monitor %s\n", dp_strerror_verbose(ret));
		return EXIT_FAILURE;
	}

	ret = do_graphtrace(&graphtrace);
	if (DP_FAILED(ret))
		fprintf(stderr, "Cannot dump graphtrace %s\n", dp_strerror_verbose(ret));

	eal_cleanup();

	return ret;
}
