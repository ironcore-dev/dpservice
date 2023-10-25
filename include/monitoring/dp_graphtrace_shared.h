#ifndef __INCLUDE_DP_GRAPHTRACE_SHARED_H__
#define __INCLUDE_DP_GRAPHTRACE_SHARED_H__

#include <rte_graph_worker.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_memzone.h>
#include <rte_ring.h>

#include "dp_mbuf_dyn.h"

#define DP_GRAPHTRACE_MEMPOOL_NAME "dp_graphtrace_mempool"
#define DP_GRAPHTRACE_RINGBUF_NAME "dp_graphtrace_ringbuf"
#define DP_GRAPHTRACE_FILTERS_NAME "dp_graphtrace_filters"

// DPDK requirement: power of 2 and less than INT32_MAX
#define DP_GRAPHTRACE_RINGBUF_SIZE 65536

#define DP_MP_ACTION_GRAPHTRACE "dp_mp_graphtrace"

#define DP_GRAPHTRACE_NODE_REGEX_MAXLEN 256
#define DP_GRAPHTRACE_FILTER_MAXLEN 1024

#ifdef __cplusplus
extern "C" {
#endif

enum dp_graphtrace_action {
	DP_GRAPHTRACE_ACTION_START,
	DP_GRAPHTRACE_ACTION_STOP,
};

struct dp_graphtrace {
	struct rte_mempool *mempool;
	struct rte_ring *ringbuf;
	const struct rte_memzone *filters;
};

struct dp_graphtrace_params {
	char node_regex[DP_GRAPHTRACE_NODE_REGEX_MAXLEN];
	char filter_string[DP_GRAPHTRACE_FILTER_MAXLEN];
};

struct dp_graphtrace_pktinfo {
	uint32_t pktid;
	const struct rte_node *node;
	const struct rte_node *next_node;
	uint16_t dst_port_id;
};

struct dp_graphtrace_params_start {
	bool drops;
	bool nodes;
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

void dp_graphtrace_sprint(const struct rte_mbuf *pkt, char *buf, size_t bufsize);

#ifdef __cplusplus
}
#endif

#endif
