#include "nodes/firewall_node.h"
#include <rte_common.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_mbuf.h>
#include "rte_flow/dp_rte_flow.h"
#include "nodes/common_node.h"
#include "dp_firewall.h"
#include "dp_log.h"

#define NEXT_NODES(NEXT) \
	NEXT(FIREWALL_NEXT_IPIP_ENCAP, "ipip_encap")
DP_NODE_REGISTER_NOINIT(FIREWALL, firewall, NEXT_NODES);

static uint16_t next_tx_index[DP_MAX_PORTS];

int firewall_node_append_vf_tx(uint16_t port_id, const char *tx_node_name)
{
	return dp_node_append_vf_tx(DP_NODE_GET_SELF(firewall), next_tx_index, port_id, tx_node_name);
}

static __rte_always_inline rte_edge_t get_next_index(__rte_unused struct rte_node *node, struct rte_mbuf *m)
{
	struct dp_flow *df = dp_get_flow_ptr(m);
	struct flow_value *cntrack = df->conntrack;
	const struct dp_port *src_port = dp_get_port(m);
	const struct dp_port *dst_port = dp_get_dst_port(df);
	enum dp_fwall_action action;

	// currently only IPv4 firewall is implemented
	if (df->l3_type == RTE_ETHER_TYPE_IPV4 && cntrack) {
		if (DP_IS_FLOW_STATUS_FLAG_FIREWALL(cntrack->flow_status)) {
			action = (enum dp_fwall_action)cntrack->fwall_action[df->flags.dir];
		} else if (df->flags.dir == DP_FLOW_DIR_ORG) {
			action = dp_get_firewall_action(df, src_port, dst_port);
			cntrack->fwall_action[DP_FLOW_DIR_ORG] = (uint8_t)action;
			cntrack->fwall_action[DP_FLOW_DIR_REPLY] = (uint8_t)action;
			cntrack->flow_status |= DP_FLOW_STATUS_FLAG_FIREWALL;
		} else
			action = DP_FWALL_DROP;
		/* Ignore the drop actions till we have the metalnet ready to set the firewall rules */
		// if (action == DP_FWALL_DROP)
		// 	return FIREWALL_NEXT_DROP;
	}

	if (dst_port->port_type == DP_PORT_PF)
		return FIREWALL_NEXT_IPIP_ENCAP;

	return next_tx_index[dst_port->port_id];
}

static uint16_t firewall_node_process(struct rte_graph *graph,
									  struct rte_node *node,
									  void **objs,
									  uint16_t nb_objs)
{
	dp_foreach_graph_packet(graph, node, objs, nb_objs, FIREWALL_NEXT_IPIP_ENCAP, get_next_index);
	return nb_objs;
}
