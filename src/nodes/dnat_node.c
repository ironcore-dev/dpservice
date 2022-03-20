#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_mbuf.h>
#include "dp_mbuf_dyn.h"
#include "dp_lpm.h"
#include "dp_flow.h"
#include "dp_util.h"
#include "nodes/dnat_node.h"


static int dnat_node_init(const struct rte_graph *graph, struct rte_node *node)
{
	struct dnat_node_ctx *ctx = (struct dnat_node_ctx *)node->ctx;

	ctx->next = DNAT_NEXT_DROP;


	RTE_SET_USED(graph);

	return 0;
}

static __rte_always_inline int handle_dnat(struct rte_mbuf *m)
{
	return 1;
}

static __rte_always_inline uint16_t dnat_node_process(struct rte_graph *graph,
													 struct rte_node *node,
													 void **objs,
													 uint16_t cnt)
{
	struct rte_mbuf *mbuf0, **pkts;
	rte_edge_t next_index;
	int i;

	pkts = (struct rte_mbuf **)objs;
	/* Speculative next */
	next_index = DNAT_NEXT_DROP;

	for (i = 0; i < cnt; i++) {
		mbuf0 = pkts[i];
		if (handle_dnat(mbuf0))
			next_index = DNAT_NEXT_IPV4_LOOKUP;
		rte_node_enqueue_x1(graph, node, next_index, mbuf0);
	}	

	return cnt;
}

static struct rte_node_register dnat_node_base = {
	.name = "dnat",
	.init = dnat_node_init,
	.process = dnat_node_process,

	.nb_edges = DNAT_NEXT_MAX,
	.next_nodes =
		{
			[DNAT_NEXT_IPV4_LOOKUP] = "ipv4_lookup",
			[DNAT_NEXT_DROP] = "drop",
		},
};

struct rte_node_register *dnat_node_get(void)
{
	return &dnat_node_base;
}

RTE_NODE_REGISTER(dnat_node_base);
