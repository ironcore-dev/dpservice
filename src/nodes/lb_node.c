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
#include "dp_lb.h"
#include "rte_flow/dp_rte_flow.h"
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
	struct rte_ipv4_hdr *ipv4_hdr;
	struct dp_flow *df_ptr;
	struct flow_key key;
	struct flow_value *cntrack = NULL;
	uint32_t dst_ip, vni;

	if (!dp_is_lb_enabled())
		return 0;

	memset(&key, 0, sizeof(struct flow_key));
	df_ptr = get_dp_flow_ptr(m);

	if (df_ptr->conntrack)
		cntrack = df_ptr->conntrack;

	if (!cntrack)
		return 1;

	if (cntrack->flow_state == DP_FLOW_STATE_NEW && cntrack->dir == DP_FLOW_DIR_ORG) {
		dst_ip = ntohl(df_ptr->dst.dst_addr);
		if (df_ptr->tun_info.dst_vni == 0)
			vni = dp_get_vm_vni(m->port);
		else
			vni = df_ptr->tun_info.dst_vni;

		if (dp_is_ip_lb(dst_ip, vni)
		    && (cntrack->flow_status == DP_FLOW_STATUS_NONE)) {
			ipv4_hdr = dp_get_ipv4_hdr(m);
			ipv4_hdr->dst_addr = htonl(dp_lb_get_backend_ip(dst_ip, vni, NULL));
			df_ptr->dst.dst_addr = ipv4_hdr->dst_addr;
			dp_nat_chg_ip(df_ptr, ipv4_hdr);

			/* Expect the new source in this conntrack object */
			cntrack->flow_status = DP_FLOW_STATUS_DST_LB;
			dp_delete_flow(&cntrack->flow_key[DP_FLOW_DIR_REPLY]);
			cntrack->flow_key[DP_FLOW_DIR_REPLY].ip_src = ntohl(ipv4_hdr->dst_addr);
			dp_add_flow(&cntrack->flow_key[DP_FLOW_DIR_REPLY]);
			dp_add_flow_data(&cntrack->flow_key[DP_FLOW_DIR_REPLY], cntrack);
			return 1;
		}
		return 0;
	}

	if (cntrack->flow_status == DP_FLOW_STATUS_DST_LB &&
		cntrack->dir == DP_FLOW_DIR_ORG) {
		ipv4_hdr = dp_get_ipv4_hdr(m);
		ipv4_hdr->dst_addr = htonl(cntrack->flow_key[DP_FLOW_DIR_REPLY].ip_src);
		df_ptr->dst.dst_addr = ipv4_hdr->dst_addr;
		dp_nat_chg_ip(df_ptr, ipv4_hdr);
	}

	return 1;
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
