#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <rte_eal.h>

#include "dp_error.h"
#include "dp_log.h"
#include "monitoring/dp_graphtrace_shared.h"
#include "rte_flow/dp_rte_flow.h"

// longest node name is 'overlay-switch'
#define NODENAME_FMT "%-14s"

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

	if (DP_FAILED(dp_graphtrace_connect(graphtrace))) {
		fprintf(stderr, "Cannot connect to service\n");
		return EXIT_FAILURE;
	}

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
			usleep(100000);
	}

	return EXIT_SUCCESS;
}

static void signal_handler(__rte_unused int signum)
{
	interrupt = true;
}

int main(void)
{
	struct dp_graphtrace graphtrace;
	int retcode;
	int ret;

	ret = eal_init();
	if (DP_FAILED(ret)) {
		fprintf(stderr, "Cannot init EAL %s\n", dp_strerror_verbose(ret));
		return EXIT_FAILURE;
	}

	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	retcode = do_graphtrace(&graphtrace);

	eal_cleanup();

	return retcode;
}
