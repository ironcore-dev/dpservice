#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_mbuf.h>
#include "node_api.h"
#include "nodes/common_node.h"
#include "nodes/l2_decap_node.h"
#include "dp_mbuf_dyn.h"
#include "dp_lpm.h"
#include "dp_util.h"
#include "rte_flow/dp_rte_flow.h"


struct l2_decap_node_main l2_decap_node;

static int l2_decap_node_init(const struct rte_graph *graph, struct rte_node *node)
{
	struct l2_decap_node_ctx *ctx = (struct l2_decap_node_ctx *)node->ctx;

	ctx->next = L2_DECAP_NEXT_DROP;

	RTE_SET_USED(graph);

	return 0;
}

static __rte_always_inline rte_edge_t get_next_index(struct rte_mbuf *m)
{
	struct dp_flow *df = get_dp_flow_ptr(m);

	/* Pop the ethernet header */
	if (df->flags.flow_type != DP_FLOW_TYPE_INCOMING)
		rte_pktmbuf_adj(m, (uint16_t)sizeof(struct rte_ether_hdr));

	if (dp_is_pf_port_id(df->nxt_hop))
		return L2_DECAP_OVERLAY_SWITCH;

	return l2_decap_node.next_index[df->nxt_hop];
} 

static uint16_t l2_decap_node_process(struct rte_graph *graph,
									  struct rte_node *node,
									  void **objs,
									  uint16_t nb_objs)
{
	dp_foreach_graph_packet(graph, node, objs, nb_objs, get_next_index);
	return nb_objs;
}

int l2_decap_set_next(uint16_t port_id, uint16_t next_index)
{
	l2_decap_node.next_index[port_id] = next_index;
	return 0;
}

static struct rte_node_register l2_decap_node_base = {
	.name = "l2_decap",
	.init = l2_decap_node_init,
	.process = l2_decap_node_process,

	.nb_edges = L2_DECAP_NEXT_MAX,
	.next_nodes =
		{
			[L2_DECAP_NEXT_DROP] = "drop",
			[L2_DECAP_OVERLAY_SWITCH] = "overlay_switch",
		},
};

struct rte_node_register *l2_decap_node_get(void)
{
	return &l2_decap_node_base;
}

RTE_NODE_REGISTER(l2_decap_node_base);
