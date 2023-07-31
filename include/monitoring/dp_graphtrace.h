#ifndef __INCLUDE_DP_GRAPHTRACE_H__
#define __INCLUDE_DP_GRAPHTRACE_H__

#ifndef ENABLE_GRAPHTRACE
#	define dp_graphtrace_node(node, obj)
#	define dp_graphtrace_node_burst(node, objs, nb_objs)
#	define dp_graphtrace_next(node, obj, next_index)
#	define dp_graphtrace_next_burst(node, objs, nb_objs, next_index)
#	define dp_graphtrace_tx_burst(node, objs, nb_objs, port_id)
#else

#include <rte_graph.h>

#include "dp_graphtrace_shared.h"

#ifdef __cplusplus
extern "C" {
#endif

enum dp_graphtrace_loglevel {
	DP_GRAPHTRACE_LOGLEVEL_SILENT,
	DP_GRAPHTRACE_LOGLEVEL_NEXT,
	DP_GRAPHTRACE_LOGLEVEL_RECV,
	DP_GRAPHTRACE_LOGLEVEL_MAX = DP_GRAPHTRACE_LOGLEVEL_RECV
};

int dp_graphtrace_init(void);
void dp_graphtrace_free(void);

void _dp_graphtrace_send(struct rte_node *node, struct rte_node *next_node, void **objs, uint16_t nb_objs, int type);

// Logging the trace for debugging
#ifdef ENABLE_PYTEST
	void _dp_graphtrace_log_node(struct rte_node *node, void *obj);
	void _dp_graphtrace_log_node_burst(struct rte_node *node, void **objs, uint16_t nb_objs);
	void _dp_graphtrace_log_next(struct rte_node *node, void *obj, rte_edge_t next_index);
	void _dp_graphtrace_log_next_burst(struct rte_node *node, void **objs, uint16_t nb_objs, rte_edge_t next_index);
	void _dp_graphtrace_log_tx_burst(struct rte_node *node, void **objs, uint16_t nb_objs, uint16_t port_id);
#else
#	define _dp_graphtrace_log_node(NODE, OBJ)
#	define _dp_graphtrace_log_node_burst(NODE, OBJS, NUM)
#	define _dp_graphtrace_log_next(NODE, OBJ, NEXT)
#	define _dp_graphtrace_log_next_burst(NODE, OBJS, NUM, NEXT)
#	define _dp_graphtrace_log_tx_burst(NODE, OBJS, NUM, PORTID)
#endif

// Currently "node entered" events are only being logged, not sent out
#define dp_graphtrace_node(NODE, OBJ) _dp_graphtrace_log_node(NODE, OBJ)
#define dp_graphtrace_node_burst(NODE, OBJS, NUM) _dp_graphtrace_log_node_burst(NODE, OBJS, NUM)

static __rte_always_inline void dp_graphtrace_next(struct rte_node *node, void *obj, rte_edge_t next_index)
{
	_dp_graphtrace_send(node, node->nodes[next_index], &obj, 1, DP_GRAPHTRACE_PKT_TYPE_SOFTWARE);
	_dp_graphtrace_log_next(node, obj, next_index);
}

static __rte_always_inline void dp_graphtrace_next_burst(struct rte_node *node, void **objs, uint16_t nb_objs, rte_edge_t next_index)
{
	_dp_graphtrace_send(node, node->nodes[next_index], objs, nb_objs, DP_GRAPHTRACE_PKT_TYPE_SOFTWARE);
	_dp_graphtrace_log_next_burst(node, objs, nb_objs, next_index);
}

static __rte_always_inline void dp_graphtrace_tx_burst(struct rte_node *node, void **objs, uint16_t nb_objs, uint16_t port_id)
{
	_dp_graphtrace_send(node, NULL, objs, nb_objs, DP_GRAPHTRACE_PKT_TYPE_SOFTWARE);
	RTE_SET_USED(port_id);
	_dp_graphtrace_log_tx_burst(node, objs, nb_objs, port_id);
}

static __rte_always_inline void dp_graphtrace_capture_offload_pkt(void *obj)
{
	_dp_graphtrace_send(NULL, NULL, &obj, 1, DP_GRAPHTRACE_PKT_TYPE_OFFLOAD);
}

#ifdef __cplusplus
}
#endif

#endif  /* ENABLE_GRAPHTRACE */

#endif
