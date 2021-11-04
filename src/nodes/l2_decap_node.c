#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_mbuf.h>
#include "node_api.h"
#include "nodes/l2_decap_node.h"
#include "dp_mbuf_dyn.h"
#include "dp_lpm.h"

struct l2_decap_node_main l2_decap_node;

static int l2_decap_node_init(const struct rte_graph *graph, struct rte_node *node)
{
	struct l2_decap_node_ctx *ctx = (struct l2_decap_node_ctx *)node->ctx;

	ctx->next = L2_DECAP_NEXT_DROP;


	RTE_SET_USED(graph);

	return 0;
}

static __rte_always_inline int handle_l2_decap(struct rte_mbuf *m)
{
	struct dp_flow *df;
	struct dp_mbuf_priv1 *dp_mbuf_p1 = NULL;

	dp_mbuf_p1 = get_dp_mbuf_priv1(m);
	if (!dp_mbuf_p1) {
		printf("Can not get private pointer\n");
		return -1;
	}
	df = dp_mbuf_p1->flow_ptr;

	/* Pop the ethernet header */
	rte_pktmbuf_adj(m, (uint16_t)sizeof(struct rte_ether_hdr));

	return df->nxt_hop;
} 

static __rte_always_inline uint16_t l2_decap_node_process(struct rte_graph *graph,
													 struct rte_node *node,
													 void **objs,
													 uint16_t cnt)
{
	struct rte_mbuf *mbuf0, **pkts;
	int i, ret;

	pkts = (struct rte_mbuf **)objs;


	for (i = 0; i < cnt; i++) {
		mbuf0 = pkts[i];
		ret = handle_l2_decap(mbuf0);
		if (ret >= 0)
			rte_node_enqueue_x1(graph, node, l2_decap_node.next_index[ret] , *objs);
		else
			rte_node_enqueue_x1(graph, node, L2_DECAP_NEXT_DROP, *objs);
	}	

    return cnt;
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
		},
};

struct rte_node_register *l2_decap_node_get(void)
{
	return &l2_decap_node_base;
}

RTE_NODE_REGISTER(l2_decap_node_base);
