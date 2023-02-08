#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_mbuf.h>
#include "dp_mbuf_dyn.h"
#include "dp_util.h"
#include "nodes/firewall_node.h"
#include "nodes/common_node.h"


static int firewall_node_init(const struct rte_graph *graph, struct rte_node *node)
{
	struct firewall_node_ctx *ctx = (struct firewall_node_ctx *)node->ctx;

	ctx->next = FIREWALL_NEXT_DROP;

	RTE_SET_USED(graph);

	return 0;
}

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

static struct rte_node_register firewall_node_base = {
	.name = "firewall",
	.init = firewall_node_init,
	.process = firewall_node_process,

	.nb_edges = FIREWALL_NEXT_MAX,
	.next_nodes =
		{
			[FIREWALL_NEXT_L2_DECAP] = "l2_decap",
			[FIREWALL_NEXT_DROP] = "drop",
		},
};

struct rte_node_register *firewall_node_get(void)
{
	return &firewall_node_base;
}

RTE_NODE_REGISTER(firewall_node_base);
