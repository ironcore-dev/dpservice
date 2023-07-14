#ifndef __INCLUDE_COMMON_NODE_H__
#define __INCLUDE_COMMON_NODE_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_mbuf.h>

#include "dp_port.h"
#include "monitoring/dp_graphtrace.h"

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
			dp_graphtrace_node(node, pkt);
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
			dp_graphtrace_node(node, pkt);
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
	RTE_SET_USED(objs);
	RTE_SET_USED(nb_objs);
	dp_graphtrace_next_burst(node, objs, nb_objs, next_index);
	rte_node_next_stream_move(graph, node, next_index);
}

//
// Functions for creating dynamic graph edges based on connectet PF/VF ports
//
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

//
// Preprocessor metaprogramming to make the node registration code simpler and more secure.
// This ensures NODE_NEXT_MAX is properly set and NODE_NEXT_DROP is always zero.
// Compiler fails if init/process callbacks are not present.
// Next nodes are DP_NODE_DEFAULT_NEXT_ONLY or extended by using a list generator macro:
//     MY_NEXT_NODES(NEXT) /
//         NEXT(MYNODE_NEXT_XXX, "xxx") /
//         NEXT(MYNODE_NEXT_YYY, "yyy") /
//     DP_NODE_REGISTER(MYNODE, mynode, MY_NEXT_NODES)
//
// The resulting `struct rte_node_register` is then accessible
// via DP_NODE_GET_SELF(mynode)
//
#define _DP_NODE_REGISTER_GENERATE_ENUM(NODE_NEXT_ENUM, NODE_NEXT_NAME) \
	NODE_NEXT_ENUM,

#define _DP_NODE_REGISTER_GENERATE_NEXT_NODES(NODE_NEXT_ENUM, NODE_NEXT_NAME) \
	[NODE_NEXT_ENUM] = NODE_NEXT_NAME,

#define _DP_NODE_REGISTER(UPPER_NODE_NAME, LOWER_NODE_NAME, EXTRA_NEXT_NODES, INIT, FLAGS) \
	static uint16_t LOWER_NODE_NAME ## _node_process(struct rte_graph *graph, struct rte_node *node, void **objs, uint16_t nb_objs); \
	enum LOWER_NODE_NAME ## _next_node { \
		UPPER_NODE_NAME ## _NEXT_DROP, \
		EXTRA_NEXT_NODES(_DP_NODE_REGISTER_GENERATE_ENUM) \
		UPPER_NODE_NAME ## _NEXT_MAX \
	}; \
	static struct rte_node_register LOWER_NODE_NAME ## _node_register = { \
		.name = #LOWER_NODE_NAME, \
		.flags = FLAGS, \
		.init = INIT, \
		.process = LOWER_NODE_NAME ## _node_process, \
		.nb_edges = UPPER_NODE_NAME ## _NEXT_MAX, \
		.next_nodes = { \
			[UPPER_NODE_NAME ## _NEXT_DROP] = "drop", \
			EXTRA_NEXT_NODES(_DP_NODE_REGISTER_GENERATE_NEXT_NODES) \
		}, \
	}; \
	RTE_NODE_REGISTER(LOWER_NODE_NAME ## _node_register)

#define _DP_NODE_REGISTER_INIT(UPPER_NODE_NAME, LOWER_NODE_NAME, EXTRA_NEXT_NODES, FLAGS) \
	static int LOWER_NODE_NAME ## _node_init(const struct rte_graph *graph, struct rte_node *node); \
	_DP_NODE_REGISTER(UPPER_NODE_NAME, LOWER_NODE_NAME, EXTRA_NEXT_NODES, LOWER_NODE_NAME ## _node_init, FLAGS)

#define DP_NODE_REGISTER_NOINIT(UPPER_NODE_NAME, LOWER_NODE_NAME, EXTRA_NEXT_NODES) \
	_DP_NODE_REGISTER(UPPER_NODE_NAME, LOWER_NODE_NAME, EXTRA_NEXT_NODES, NULL, 0)

#define DP_NODE_REGISTER_SOURCE(UPPER_NODE_NAME, LOWER_NODE_NAME, EXTRA_NEXT_NODES) \
	_DP_NODE_REGISTER_INIT(UPPER_NODE_NAME, LOWER_NODE_NAME, EXTRA_NEXT_NODES, RTE_NODE_SOURCE_F)

#define DP_NODE_REGISTER(UPPER_NODE_NAME, LOWER_NODE_NAME, EXTRA_NEXT_NODES) \
	_DP_NODE_REGISTER_INIT(UPPER_NODE_NAME, LOWER_NODE_NAME, EXTRA_NEXT_NODES, 0)

#define DP_NODE_GET_SELF(LOWER_NODE_NAME) (&LOWER_NODE_NAME ## _node_register)

#define DP_NODE_DEFAULT_NEXT_ONLY(NEXT)

#ifdef __cplusplus
}
#endif

#endif
