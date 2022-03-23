#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_mbuf.h>
#include "dp_mbuf_dyn.h"
#include "dp_lpm.h"
#include "dp_flow.h"
#include "dp_util.h"
#include "nodes/firewall_node.h"


static int firewall_node_init(const struct rte_graph *graph, struct rte_node *node)
{
	struct firewall_node_ctx *ctx = (struct firewall_node_ctx *)node->ctx;

	ctx->next = FIREWALL_NEXT_DROP;


	RTE_SET_USED(graph);

	return 0;
}

static __rte_always_inline int handle_firewall(struct rte_mbuf *m)
{
	return DP_FIREWL_PASS_PACKET;
}

static __rte_always_inline uint16_t firewall_node_process(struct rte_graph *graph,
													 struct rte_node *node,
													 void **objs,
													 uint16_t cnt)
{
	struct rte_mbuf *mbuf0, **pkts;
	rte_edge_t next_index;
	int i;

	pkts = (struct rte_mbuf **)objs;
	/* Speculative next */
	next_index = FIREWALL_NEXT_DROP;

	for (i = 0; i < cnt; i++) {
		mbuf0 = pkts[i];
		if (handle_firewall(mbuf0))
			next_index = FIREWALL_NEXT_L2_DECAP;
		else
			printf("drop a packet by firewall \n");
		rte_node_enqueue_x1(graph, node, next_index, mbuf0);
	}	

	return cnt;
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
