#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_mbuf.h>
#include "node_api.h"
#include "nodes/l2_decap_node.h"
#include "dp_mbuf_dyn.h"
#include "dp_lpm.h"
#include "dp_util.h"

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
	df = get_dp_flow_ptr(m);

	/* Pop the ethernet header */
	// if (!df->flags.geneve_hdr || !df->flags.srv6_hdr) {
	if ( !df->flags.srv6_hdr) {
		rte_pktmbuf_adj(m, (uint16_t)sizeof(struct rte_ether_hdr));
	}

	return df->nxt_hop;
} 

static __rte_always_inline uint16_t l2_decap_node_process(struct rte_graph *graph,
													 struct rte_node *node,
													 void **objs,
													 uint16_t cnt)
{
	struct rte_mbuf *mbuf0, **pkts;
	int i, ret;
	
	struct dp_flow *df;

	pkts = (struct rte_mbuf **)objs;


	for (i = 0; i < cnt; i++) {
		mbuf0 = pkts[i];
		ret = handle_l2_decap(mbuf0);
		if (!dp_is_pf_port_id(ret)) {
			rte_node_enqueue_x1(graph, node, l2_decap_node.next_index[ret], mbuf0);
		}
		else {
			df = get_dp_flow_ptr(mbuf0);

			if (df->flags.encap_type==DP_ENCAP_TYPE_GENEVE){
				rte_node_enqueue_x1(graph, node, L2_DECAP_NEXT_GENEVE_ENCAP, mbuf0);
			}
			else if (df->flags.encap_type==DP_ENCAP_TYPE_SRV6) {
				rte_node_enqueue_x1(graph, node, L2_DECAP_NEXT_SRV6_ENCAP, mbuf0);
			}

		}
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
			[L2_DECAP_NEXT_GENEVE_ENCAP] = "geneve_encap",
			[L2_DECAP_NEXT_SRV6_ENCAP] = "srv6_encap",
		},
};

struct rte_node_register *l2_decap_node_get(void)
{
	return &l2_decap_node_base;
}

RTE_NODE_REGISTER(l2_decap_node_base);
