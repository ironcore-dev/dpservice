#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_mbuf.h>
#include "dp_mbuf_dyn.h"
#include "dp_lpm.h"
#include "dp_flow.h"
#include "dp_util.h"
#include "dp_rte_flow.h"
#include "nodes/conntrack_node.h"


static int conntrack_node_init(const struct rte_graph *graph, struct rte_node *node)
{
	struct conntrack_node_ctx *ctx = (struct conntrack_node_ctx *)node->ctx;

	ctx->next = CONNTRACK_NEXT_DROP;


	RTE_SET_USED(graph);

	return 0;
}

static __rte_always_inline int handle_conntrack(struct rte_mbuf *m)
{
	struct rte_ipv4_hdr *ipv4_hdr;
	struct dp_flow *df_ptr;
	int ret = 0;

	df_ptr = get_dp_flow_ptr(m);

	if (df_ptr->flags.flow_type == DP_FLOW_TYPE_INCOMING)
		ipv4_hdr = rte_pktmbuf_mtod(m, struct rte_ipv4_hdr *);
	else
		ipv4_hdr = rte_pktmbuf_mtod_offset(m, struct rte_ipv4_hdr *,
										   sizeof(struct rte_ether_hdr));

	if (extract_inner_l3_header(m, ipv4_hdr, 0) < 0)
		return DP_ROUTE_DROP;

	if (extract_inner_l4_header(m, ipv4_hdr + 1, 0) < 0)
		return DP_ROUTE_DROP;

	return ret;
}

static __rte_always_inline uint16_t conntrack_node_process(struct rte_graph *graph,
													 struct rte_node *node,
													 void **objs,
													 uint16_t cnt)
{
	struct rte_mbuf *mbuf0, **pkts;
	int i, route;

	pkts = (struct rte_mbuf **)objs;

	for (i = 0; i < cnt; i++) {
		mbuf0 = pkts[i];
		route = handle_conntrack(mbuf0);

		if (route >= 0) 
			rte_node_enqueue_x1(graph, node, CONNTRACK_NEXT_DNAT, 
								mbuf0);
		else
			rte_node_enqueue_x1(graph, node, CONNTRACK_NEXT_DROP, mbuf0);
	}	

	return cnt;
}

static struct rte_node_register conntrack_node_base = {
	.name = "conntrack",
	.init = conntrack_node_init,
	.process = conntrack_node_process,

	.nb_edges = CONNTRACK_NEXT_MAX,
	.next_nodes =
		{
			[CONNTRACK_NEXT_DNAT] = "dnat",
			//[CONNTRACK_NEXT_LB] = "lb",
			[CONNTRACK_NEXT_DROP] = "drop",
		},
};

struct rte_node_register *conntrack_node_get(void)
{
	return &conntrack_node_base;
}

RTE_NODE_REGISTER(conntrack_node_base);
