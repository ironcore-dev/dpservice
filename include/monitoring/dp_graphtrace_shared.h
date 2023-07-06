#ifndef __INCLUDE_DP_GRAPHTRACE_SHARED_H__
#define __INCLUDE_DP_GRAPHTRACE_SHARED_H__

#include <rte_graph_worker.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_ring.h>

#include "dp_mbuf_dyn.h"

#define DP_GRAPHTRACE_MEMPOOL_NAME "dp_graphtrace_mempool"
#define DP_GRAPHTRACE_RINGBUF_NAME "dp_graphtrace_ringbuf"

// DPDK requirement: power of 2 and less than INT32_MAX
#define DP_GRAPHTRACE_RINGBUF_SIZE 65536

#ifdef __cplusplus
extern "C" {
#endif

struct dp_graphtrace {
	struct rte_mempool	*mempool;
	struct rte_ring		*ringbuf;
};

struct dp_graphtrace_pktinfo {
	uint32_t pktid;
	struct rte_node *node;
	struct rte_node *next_node;
};

static inline struct dp_graphtrace_pktinfo *dp_get_graphtrace_pktinfo(struct rte_mbuf *pkt)
{
	return (struct dp_graphtrace_pktinfo *)(dp_get_flow_ptr(pkt) + 1);
}

void dp_graphtrace_sprint(struct rte_mbuf *pkt, char *buf, size_t bufsize);

#ifdef __cplusplus
}
#endif

#endif
