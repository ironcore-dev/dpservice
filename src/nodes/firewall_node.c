#include <rte_common.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_mbuf.h>
#include "nodes/common_node.h"

#define NEXT_NODES(NEXT) \
	NEXT(FIREWALL_NEXT_L2_DECAP, "l2_decap")
DP_NODE_REGISTER_NOINIT(FIREWALL, firewall, NEXT_NODES);

static __rte_always_inline rte_edge_t get_next_index(__rte_unused struct rte_node *node, struct rte_mbuf *m)
{
	return FIREWALL_NEXT_L2_DECAP;
}

static uint16_t firewall_node_process(struct rte_graph *graph,
									  struct rte_node *node,
									  void **objs,
									  uint16_t nb_objs)
{
	dp_foreach_graph_packet(graph, node, objs, nb_objs, FIREWALL_NEXT_L2_DECAP, get_next_index);
	return nb_objs;
}
