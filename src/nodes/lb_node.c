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
#include "dp_alias.h"
#include "rte_flow/dp_rte_flow.h"
#include "nodes/common_node.h"
#include "nodes/lb_node.h"


static int lb_node_init(const struct rte_graph *graph, struct rte_node *node)
{
	struct lb_node_ctx *ctx = (struct lb_node_ctx *)node->ctx;

	ctx->next = LB_NEXT_DROP;

	RTE_SET_USED(graph);

	return 0;
}

static __rte_always_inline void lb_alias_check(struct dp_flow *df_ptr, uint16_t port)
{
	df_ptr->flags.flow_type = DP_FLOW_TYPE_OUTGOING;
	df_ptr->nxt_hop = port;
	if (dp_get_portid_with_alias_handle(df_ptr->tun_info.ul_dst_addr6) == -1)
		df_ptr->flags.nat = DP_LB_CHG_UL_DST_IP;
	else
		df_ptr->flags.nat = DP_LB_RECIRC;
}

static __rte_always_inline rte_edge_t get_next_index(struct rte_mbuf *m)
{
	struct dp_flow *df_ptr = get_dp_flow_ptr(m);
	struct flow_value *cntrack = df_ptr->conntrack;
	uint32_t dst_ip, vni;
	uint8_t *target_ip6;

	if (!cntrack)
		return LB_NEXT_DNAT;

	dst_ip = ntohl(df_ptr->dst.dst_addr);
	vni = df_ptr->tun_info.dst_vni == 0 ? dp_get_vm_vni(m->port) : df_ptr->tun_info.dst_vni;

	if (cntrack->flow_state == DP_FLOW_STATE_NEW
		&& cntrack->dir == DP_FLOW_DIR_ORG
		&& dp_is_ip_lb(dst_ip, vni)
		&& cntrack->flow_status == DP_FLOW_STATUS_NONE
	) {
		if (df_ptr->l4_type == IPPROTO_ICMP) {
			df_ptr->flags.nat = DP_LB_CHG_UL_DST_IP;
			return LB_NEXT_PACKET_RELAY;
		}

		target_ip6 = dp_lb_get_backend_ip(dst_ip, vni, df_ptr->dst_port, df_ptr->l4_type);
		if (!target_ip6)
			return LB_NEXT_DROP;

		memcpy(df_ptr->tun_info.ul_dst_addr6, target_ip6, sizeof(df_ptr->tun_info.ul_dst_addr6));
		memcpy(cntrack->lb_dst_addr6, df_ptr->tun_info.ul_dst_addr6, sizeof(df_ptr->tun_info.ul_dst_addr6));
		cntrack->flow_status = DP_FLOW_STATUS_DST_LB;
		lb_alias_check(df_ptr, m->port);
		return LB_NEXT_OVERLAY_SWITCH;
	}

	if (cntrack->flow_status == DP_FLOW_STATUS_DST_LB && cntrack->dir == DP_FLOW_DIR_ORG) {
		memcpy(df_ptr->tun_info.ul_dst_addr6, cntrack->lb_dst_addr6, sizeof(df_ptr->tun_info.ul_dst_addr6));
		lb_alias_check(df_ptr, m->port);
		return LB_NEXT_OVERLAY_SWITCH;
	}

	return LB_NEXT_DNAT;
}

static uint16_t lb_node_process(struct rte_graph *graph,
								struct rte_node *node,
								void **objs,
								uint16_t nb_objs)
{
	if (dp_is_lb_enabled())
		dp_foreach_graph_packet(graph, node, objs, nb_objs, get_next_index);
	else
		dp_forward_graph_packets(graph, node, objs, nb_objs, LB_NEXT_DNAT);

	return nb_objs;
}

static struct rte_node_register lb_node_base = {
	.name = "lb",
	.init = lb_node_init,
	.process = lb_node_process,

	.nb_edges = LB_NEXT_MAX,
	.next_nodes =
		{
			[LB_NEXT_OVERLAY_SWITCH] = "overlay_switch",
			[LB_NEXT_PACKET_RELAY] = "packet_relay",
			[LB_NEXT_DNAT] = "dnat",
			[LB_NEXT_DROP] = "drop",
		},
};

struct rte_node_register *lb_node_get(void)
{
	return &lb_node_base;
}

RTE_NODE_REGISTER(lb_node_base);
