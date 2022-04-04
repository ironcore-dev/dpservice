#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_mbuf.h>
#include "dp_mbuf_dyn.h"
#include "dp_lpm.h"
#include "dp_nat.h"
#include "dp_flow.h"
#include "dp_util.h"
#include "nodes/lb_node.h"


static int lb_node_init(const struct rte_graph *graph, struct rte_node *node)
{
	struct lb_node_ctx *ctx = (struct lb_node_ctx *)node->ctx;

	ctx->next = LB_NEXT_DROP;


	RTE_SET_USED(graph);

	return 0;
}

static __rte_always_inline int handle_lb(struct rte_mbuf *m)
{
	//struct rte_ipv4_hdr *ipv4_hdr;
	//struct rte_tcp_hdr *tcp_hdr;
	struct dp_flow *df_ptr;
	struct flow_key key;
	struct flow_value *cntrack = NULL;
	//uint32_t dst_ip, vni;

	memset(&key, 0, sizeof(struct flow_key));
	df_ptr = get_dp_flow_ptr(m);

	if (df_ptr->conntrack)
		cntrack = df_ptr->conntrack;

	if (!cntrack)
		return 1;

	return 0;
}

static __rte_always_inline uint16_t lb_node_process(struct rte_graph *graph,
													 struct rte_node *node,
													 void **objs,
													 uint16_t cnt)
{
	struct rte_mbuf *mbuf0, **pkts;
	rte_edge_t next_index;
	int i;

	pkts = (struct rte_mbuf **)objs;
	/* Speculative next */
	next_index = LB_NEXT_DROP;

	for (i = 0; i < cnt; i++) {
		mbuf0 = pkts[i];
		if (handle_lb(mbuf0))
			next_index = LB_NEXT_IPV4_LOOKUP;
		else
			next_index = LB_NEXT_DNAT;
		rte_node_enqueue_x1(graph, node, next_index, mbuf0);
	}	

	return cnt;
}

static struct rte_node_register lb_node_base = {
	.name = "lb",
	.init = lb_node_init,
	.process = lb_node_process,

	.nb_edges = LB_NEXT_MAX,
	.next_nodes =
		{
			[LB_NEXT_IPV4_LOOKUP] = "ipv4_lookup",
			[LB_NEXT_DNAT] = "dnat",
			[LB_NEXT_DROP] = "drop",
		},
};

struct rte_node_register *lb_node_get(void)
{
	return &lb_node_base;
}

RTE_NODE_REGISTER(lb_node_base);
