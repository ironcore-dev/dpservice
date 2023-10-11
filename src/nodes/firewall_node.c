#include <rte_common.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_mbuf.h>
#include "rte_flow/dp_rte_flow.h"
#include "nodes/common_node.h"
#include "dp_firewall.h"
#include "dp_log.h"

#define NEXT_NODES(NEXT) \
	NEXT(FIREWALL_NEXT_L2_DECAP, "l2_decap")
DP_NODE_REGISTER_NOINIT(FIREWALL, firewall, NEXT_NODES);

static __rte_always_inline rte_edge_t get_next_index(__rte_unused struct rte_node *node, struct rte_mbuf *m)
{
	struct dp_flow *df = dp_get_flow_ptr(m);
	struct flow_value *cntrack = df->conntrack;
	enum dp_fwall_action action;

	if (!DP_IS_FLOW_STATUS_FLAG_FIREWALL(cntrack->flow_status) && df->flags.dir == DP_FLOW_DIR_ORG) {
		action = dp_get_firewall_action(m);
		cntrack->fwall_action[DP_FLOW_DIR_ORG] = (uint8_t)action;
		cntrack->fwall_action[DP_FLOW_DIR_REPLY] = (uint8_t)action;
	}

	if (DP_IS_FLOW_STATUS_FLAG_FIREWALL(cntrack->flow_status))
		action = (enum dp_fwall_action)cntrack->fwall_action[df->flags.dir];

	/* Ignore the drop actions till we have the metalnet ready to set the firewall rules */
	/*if (action == DP_FWALL_DROP)
		return FIREWALL_NEXT_DROP;*/

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
