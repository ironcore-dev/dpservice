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

#define DP_MP_ACTION_GRAPHTRACE "dp_mp_graphtrace"

#ifdef __cplusplus
extern "C" {
#endif

enum dp_graphtrace_action {
	DP_GRAPHTRACE_ACTION_START,
	DP_GRAPHTRACE_ACTION_STOP,
};

enum dp_graphtrace_pkt_type {
	DP_GRAPHTRACE_PKT_TYPE_SOFTWARE,
	DP_GRAPHTRACE_PKT_TYPE_OFFLOAD,
};

struct dp_graphtrace {
	struct rte_mempool	*mempool;
	struct rte_ring		*ringbuf;
};

struct dp_graphtrace_pktinfo {
	enum dp_graphtrace_pkt_type pkt_type;
	uint32_t pktid;
	struct rte_node *node;
	struct rte_node *next_node;
	uint16_t dst_port_id;
};

struct dp_graphtrace_params_start {
	bool drops;
	bool nodes;
	bool hw;
};

struct dp_graphtrace_mp_request {
	enum dp_graphtrace_action action;
	union {
		struct dp_graphtrace_params_start start;
	} params;
};

struct dp_graphtrace_mp_reply {
	int error_code;
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
