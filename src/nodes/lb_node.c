#include <rte_common.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_mbuf.h>
#include "dp_error.h"
#include "dp_flow.h"
#include "dp_lb.h"
#include "dp_mbuf_dyn.h"
#include "dp_nat.h"
#include "dp_vnf.h"
#include "nodes/common_node.h"
#include "rte_flow/dp_rte_flow.h"

#define NEXT_NODES(NEXT) \
	NEXT(LB_NEXT_IPIP_ENCAP, "ipip_encap") \
	NEXT(LB_NEXT_PACKET_RELAY, "packet_relay") \
	NEXT(LB_NEXT_DNAT, "dnat")
DP_NODE_REGISTER_NOINIT(LB, lb, NEXT_NODES);

static __rte_always_inline void dp_lb_set_next_hop(struct dp_flow *df, uint16_t port_id)
{
	df->flags.flow_type = DP_FLOW_TYPE_OUTGOING; // for recirc pkt, it will be changed back to DP_FLOW_TYPE_INCOMING in cls_node.c
	if (DP_FAILED(dp_get_portid_with_vnf_key(df->tun_info.ul_dst_addr6, DP_VNF_TYPE_LB_ALIAS_PFX))) {
		df->nxt_hop = port_id;  // needs to validated by the caller!
		df->flags.nat = DP_CHG_UL_DST_IP;
	} else
		df->flags.nat = DP_LB_RECIRC;
}

static __rte_always_inline rte_edge_t get_next_index(__rte_unused struct rte_node *node, struct rte_mbuf *m)
{
	struct dp_flow *df = dp_get_flow_ptr(m);
	struct flow_value *cntrack = df->conntrack;
	struct flow_key *flow_key;
	uint32_t dst_ip, vni;
	uint8_t *target_ip6;

	if (!cntrack)
		return LB_NEXT_DNAT;

	dst_ip = ntohl(df->dst.dst_addr);
	vni = df->tun_info.dst_vni;
	if (vni == 0)
		vni = dp_get_port(m)->vm.vni;

	if (DP_IS_FLOW_STATUS_FLAG_NONE(cntrack->flow_status)
		&& df->flags.dir == DP_FLOW_DIR_ORG
		&& dp_is_ip_lb(dst_ip, vni)
	) {
		if (df->l4_type == IPPROTO_ICMP) {
			/* Directly answer echo replies of loadbalanced IP, do not forward */
			if (df->l4_info.icmp_field.icmp_type == RTE_IP_ICMP_ECHO_REQUEST) {
				df->flags.nat = DP_CHG_UL_DST_IP;
				return LB_NEXT_PACKET_RELAY;
			}
			/* ICMP error types conntrack keys are built from original TCP/UDP header, so let them slip */
			if (df->l4_info.icmp_field.icmp_type != DP_IP_ICMP_TYPE_ERROR)
				return LB_NEXT_DROP;
		}

		flow_key = &cntrack->flow_key[DP_FLOW_DIR_ORG];
		target_ip6 = dp_lb_get_backend_ip(dst_ip, vni, htons(flow_key->port_dst), flow_key->proto);
		if (!target_ip6)
			return LB_NEXT_DROP;

		rte_memcpy(df->tun_info.ul_src_addr6, df->tun_info.ul_dst_addr6, sizeof(df->tun_info.ul_src_addr6)); // same trick as in packet_relay_node.c
		rte_memcpy(df->tun_info.ul_dst_addr6, target_ip6, sizeof(df->tun_info.ul_dst_addr6));
		rte_memcpy(cntrack->nf_info.underlay_dst, df->tun_info.ul_dst_addr6, sizeof(df->tun_info.ul_dst_addr6));
		cntrack->flow_status |= DP_FLOW_STATUS_FLAG_DST_LB;
		dp_lb_set_next_hop(df, m->port);

		if (df->flags.nat != DP_LB_RECIRC) {
			cntrack->nf_info.nat_type = DP_FLOW_LB_TYPE_FORWARD;
			dp_delete_flow(&cntrack->flow_key[DP_FLOW_DIR_REPLY]); // no reverse traffic for relaying pkts
		} else
			cntrack->nf_info.nat_type = DP_FLOW_LB_TYPE_RECIRC;

		return LB_NEXT_IPIP_ENCAP;
	}

	if (DP_IS_FLOW_STATUS_FLAG_DST_LB(cntrack->flow_status) && df->flags.dir == DP_FLOW_DIR_ORG) {
		rte_memcpy(df->tun_info.ul_src_addr6, df->tun_info.ul_dst_addr6, sizeof(df->tun_info.ul_src_addr6));
		rte_memcpy(df->tun_info.ul_dst_addr6, cntrack->nf_info.underlay_dst, sizeof(df->tun_info.ul_dst_addr6));
		dp_lb_set_next_hop(df, m->port);
		return LB_NEXT_IPIP_ENCAP;
	}

	if (DP_IS_FLOW_STATUS_FLAG_DEFAULT(cntrack->flow_status) && df->l4_type == IPPROTO_ICMP) {
		df->flags.nat = DP_CHG_UL_DST_IP;
		return LB_NEXT_PACKET_RELAY;
	}

	return LB_NEXT_DNAT;
}

static uint16_t lb_node_process(struct rte_graph *graph,
								struct rte_node *node,
								void **objs,
								uint16_t nb_objs)
{
	if (dp_is_lb_enabled())
		dp_foreach_graph_packet(graph, node, objs, nb_objs, LB_NEXT_DNAT, get_next_index);
	else
		dp_forward_graph_packets(graph, node, objs, nb_objs, LB_NEXT_DNAT);

	return nb_objs;
}
