#include "nodes/l2_decap_node.h"
#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_mbuf.h>
#include "dp_lpm.h"
#include "dp_mbuf_dyn.h"
#include "dp_util.h"
#include "node_api.h"
#include "nodes/common_node.h"
#include "rte_flow/dp_rte_flow.h"

enum {
	L2_DECAP_NEXT_DROP,
	L2_DECAP_OVERLAY_SWITCH,
	L2_DECAP_NEXT_MAX
};

static uint16_t next_tx_index[DP_MAX_PORTS];

static __rte_always_inline rte_edge_t get_next_index(__rte_unused struct rte_node *node, struct rte_mbuf *m)
{
	struct dp_flow *df = get_dp_flow_ptr(m);

	/* Pop the ethernet header */
	if (df->flags.flow_type != DP_FLOW_TYPE_INCOMING) {
		rte_pktmbuf_adj(m, (uint16_t)sizeof(struct rte_ether_hdr));
		m->packet_type &= ~RTE_PTYPE_L2_ETHER;
	}

	if (dp_port_is_pf(df->nxt_hop))
		return L2_DECAP_OVERLAY_SWITCH;

	return next_tx_index[df->nxt_hop];
} 

static uint16_t l2_decap_node_process(struct rte_graph *graph,
									  struct rte_node *node,
									  void **objs,
									  uint16_t nb_objs)
{
	dp_foreach_graph_packet(graph, node, objs, nb_objs, L2_DECAP_OVERLAY_SWITCH, get_next_index);
	return nb_objs;
}

static struct rte_node_register l2_decap_node_base = {
	.name = "l2_decap",
	.init = NULL,
	.process = l2_decap_node_process,
	.nb_edges = L2_DECAP_NEXT_MAX,
	.next_nodes = {
		[L2_DECAP_NEXT_DROP] = "drop",
		[L2_DECAP_OVERLAY_SWITCH] = "overlay_switch",
	},
};
RTE_NODE_REGISTER(l2_decap_node_base);

int l2_decap_node_append_vf_tx(uint16_t port_id, const char *tx_node_name)
{
	return dp_node_append_vf_tx(&l2_decap_node_base, next_tx_index, port_id, tx_node_name);
}
