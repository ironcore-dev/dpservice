#ifndef __INCLUDE_COMMON_NODE_H__
#define __INCLUDE_COMMON_NODE_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_mbuf.h>

#include "dp_conf.h"
#include "dp_port.h"

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

enum {
	DP_GRAPHTRACE_LEVEL_SILENT,
	DP_GRAPHTRACE_LEVEL_EDGES,
	DP_GRAPHTRACE_LEVEL_NODES,
	DP_GRAPHTRACE_LEVEL_MAX = DP_GRAPHTRACE_LEVEL_NODES
};
#endif

#define DP_GRAPH_NO_SPECULATED_NODE -1

static __rte_always_inline
void dp_foreach_graph_packet(struct rte_graph *graph,
							 struct rte_node *node,
							 void **objs,
							 uint16_t nb_objs,
							 int32_t speculated_node,
							 rte_edge_t (*get_next_index)(struct rte_node *node,
														  struct rte_mbuf *pkt))
{
	struct rte_mbuf *pkt;
	rte_edge_t next_index, speculated_next_node_index;
	uint i;
	void **to_next, **from;
	uint16_t last_spec = 0;
	uint16_t held = 0;

	// If there is a valid speculated node, the pkts are moved to next node using rte_node_next_stream_move
	// otherwise, always using rte_node_enqueue_x1
	if (speculated_node >= 0) {
		speculated_next_node_index = (rte_edge_t)speculated_node;
		from = objs;
		to_next = rte_node_next_stream_get(graph, node, speculated_next_node_index, nb_objs);
		for (i = 0; i < nb_objs; ++i) {
			pkt = (struct rte_mbuf *)objs[i];
			rte_prefetch0(objs[i+1]);
			dp_graphtrace(node, pkt);
			next_index = get_next_index(node, pkt);

			if (unlikely(next_index != speculated_next_node_index)) {
				rte_memcpy(to_next, from, last_spec * sizeof(from[0]));
				from += last_spec;
				to_next += last_spec;
				held += last_spec;
				last_spec = 0;

				rte_node_enqueue_x1(graph, node, next_index, from[0]);
				from += 1;
			} else {
				last_spec += 1;
			}
			dp_graphtrace_next(node, pkt, next_index);
		}

		if (likely(last_spec == nb_objs)) {
			rte_node_next_stream_move(graph, node, speculated_next_node_index);
			return;
		}

		held += last_spec;
		rte_memcpy(to_next, from, last_spec * sizeof(from[0]));
		rte_node_next_stream_put(graph, node, speculated_next_node_index, held);
	} else {

		for (i = 0; i < nb_objs; ++i) {
			pkt = (struct rte_mbuf *)objs[i];
			// __builtin_prefetch(&objs[i+1]);
			dp_graphtrace(node, pkt);
			next_index = get_next_index(node, pkt);
			dp_graphtrace_next(node, pkt, next_index);
			rte_node_enqueue_x1(graph, node, next_index, pkt);
		}

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

int dp_node_append_tx(struct rte_node_register *node,
					  uint16_t next_tx_indices[DP_MAX_PORTS],
					  uint16_t port_id,
					  const char *tx_node_name);
int dp_node_append_vf_tx(struct rte_node_register *node,
						 uint16_t next_tx_indices[DP_MAX_PORTS],
						 uint16_t port_id,
						 const char *tx_node_name);
int dp_node_append_pf_tx(struct rte_node_register *node,
						 uint16_t next_tx_indices[DP_MAX_PORTS],
						 uint16_t port_id,
						 const char *tx_node_name);

#ifdef __cplusplus
}
#endif

#endif
