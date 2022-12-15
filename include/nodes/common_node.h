#ifndef __INCLUDE_COMMON_NODE_H__
#define __INCLUDE_COMMON_NODE_H__

#include "node_api.h"
#include "dp_util.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef ENABLE_GRAPHTRACE
#	define dp_graphtrace_burst(node, objs, nb_objs)
#	define dp_graphtrace_burst_next(node, objs, nb_objs, next_index)
#	define dp_graphtrace_burst_tx(node, objs, nb_objs, port_id)
#	define dp_graphtrace(node, obj)
#	define dp_graphtrace_next(node, obj, next_index)
#else
void dp_graphtrace_burst(struct rte_node *node, void **objs, uint16_t nb_objs);
void dp_graphtrace_burst_next(struct rte_node *node, void **objs, uint16_t nb_objs, rte_edge_t next_index);
void dp_graphtrace_burst_tx(struct rte_node *node, void **objs, uint16_t nb_objs, uint16_t port_id);
void dp_graphtrace(struct rte_node *node, void *obj);
void dp_graphtrace_next(struct rte_node *node, void *obj, rte_edge_t next_index);
#endif

static __rte_always_inline
void dp_foreach_graph_packet(struct rte_graph *graph,
							 struct rte_node *node,
							 void **objs,
							 uint16_t nb_objs,
							 rte_edge_t (*get_next_index)(struct rte_mbuf *pkt))
{
	struct rte_mbuf *pkt;
	rte_edge_t next_index;
	uint i;

	for (i = 0; i < nb_objs; ++i) {
		pkt = (struct rte_mbuf *)objs[i];
		dp_graphtrace(node, pkt);
		next_index = get_next_index(pkt);
		dp_graphtrace_next(node, pkt, next_index);
		rte_node_enqueue_x1(graph, node, next_index, pkt);
	}
}

static __rte_always_inline
void dp_forward_graph_packets(struct rte_graph *graph,
							 struct rte_node *node,
							 void **objs,
							 uint16_t nb_objs,
							 rte_edge_t next_index)
{
	dp_graphtrace_burst_next(node, objs, nb_objs, next_index);
	rte_node_next_stream_move(graph, node, next_index);
}

#ifdef __cplusplus
}
#endif

#endif
