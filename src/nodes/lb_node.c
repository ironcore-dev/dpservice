// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

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
#include "protocols/dp_icmpv6.h"
#include "nodes/common_node.h"
#include "rte_flow/dp_rte_flow.h"

#define NEXT_NODES(NEXT) \
	NEXT(LB_NEXT_IPIP_ENCAP, "ipip_encap") \
	NEXT(LB_NEXT_PACKET_RELAY, "packet_relay") \
	NEXT(LB_NEXT_DNAT, "dnat")
DP_NODE_REGISTER_NOINIT(LB, lb, NEXT_NODES);

static __rte_always_inline void dp_lb_set_next_hop(struct dp_flow *df, uint16_t port_id)
{
	const struct dp_vnf *vnf;

	vnf = dp_get_vnf(&df->tun_info.ul_dst_addr6);
	if (!vnf || vnf->type != DP_VNF_TYPE_LB_ALIAS_PFX) {
		df->nxt_hop = port_id;  // needs to validated by the caller (but it's always m->port)
		df->nat_type = DP_CHG_UL_DST_IP;
	} else
		df->nat_type = DP_LB_RECIRC;
}

static __rte_always_inline rte_edge_t get_next_index(__rte_unused struct rte_node *node, struct rte_mbuf *m)
{
	struct dp_flow *df = dp_get_flow_ptr(m);
	struct flow_value *cntrack = df->conntrack;
	const union dp_ipv6 *target_ip6;
	uint32_t vni;

	if (!cntrack)
		return LB_NEXT_DNAT;

	vni = df->tun_info.dst_vni;
	if (vni == 0)
		vni = dp_get_in_port(m)->iface.vni;

	if (DP_FLOW_HAS_NO_FLAGS(cntrack->flow_flags)
		&& df->flow_dir == DP_FLOW_DIR_ORG
		&& dp_is_ip_lb(df, vni)
	) {
		if (df->l4_type == IPPROTO_ICMP || df->l4_type == IPPROTO_ICMPV6) {
			/* Directly answer echo replies of loadbalanced IP, do not forward */
			if (df->l4_info.icmp_field.icmp_type == RTE_IP_ICMP_ECHO_REQUEST
			    || df->l4_info.icmp_field.icmp_type == DP_ICMPV6_ECHO_REQUEST
			) {
				df->nat_type = DP_CHG_UL_DST_IP;
				cntrack->offload_state.orig = DP_FLOW_OFFLOADED;
				cntrack->offload_state.reply = DP_FLOW_OFFLOADED;
				df->offload_state = DP_FLOW_NON_OFFLOAD;
				return LB_NEXT_PACKET_RELAY;
			}
			/* ICMP error types conntrack keys are built from original TCP/UDP header, so let them slip */
			if (df->l4_info.icmp_field.icmp_type != DP_IP_ICMP_TYPE_ERROR)
				return LB_NEXT_DROP;
		}

		target_ip6 = dp_lb_get_backend_ip(&cntrack->flow_key[DP_FLOW_DIR_ORG], vni);
		if (!target_ip6)
			return LB_NEXT_DROP;

		dp_copy_ipv6(&df->tun_info.ul_src_addr6, &df->tun_info.ul_dst_addr6);  // same trick as in packet_relay_node.c
		dp_copy_ipv6(&df->tun_info.ul_dst_addr6, target_ip6);
		dp_copy_ipv6(&cntrack->nf_info.underlay_dst, target_ip6);
		cntrack->flow_flags |= DP_FLOW_FLAG_DST_LB;
		dp_lb_set_next_hop(df, m->port);

		if (df->nat_type != DP_LB_RECIRC) {
			cntrack->nf_info.nat_type = DP_FLOW_LB_TYPE_FORWARD;
			dp_delete_flow(&cntrack->flow_key[DP_FLOW_DIR_REPLY]); // no reverse traffic for relaying pkts
		} else
			cntrack->nf_info.nat_type = DP_FLOW_LB_TYPE_RECIRC;

		return LB_NEXT_IPIP_ENCAP;
	}

	if (DP_FLOW_HAS_FLAG_DST_LB(cntrack->flow_flags) && df->flow_dir == DP_FLOW_DIR_ORG) {
		dp_copy_ipv6(&df->tun_info.ul_src_addr6, &df->tun_info.ul_dst_addr6);
		dp_copy_ipv6(&df->tun_info.ul_dst_addr6, &cntrack->nf_info.underlay_dst);
		dp_lb_set_next_hop(df, m->port);
		return LB_NEXT_IPIP_ENCAP;
	}

	if (DP_FLOW_HAS_FLAG_DEFAULT(cntrack->flow_flags) && (df->l4_type == IPPROTO_ICMP || df->l4_type == IPPROTO_ICMPV6)) {
		df->nat_type = DP_CHG_UL_DST_IP;
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
