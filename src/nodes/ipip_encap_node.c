// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#include "nodes/ipip_encap_node.h"
#include <rte_common.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_mbuf.h>
#include "dp_mbuf_dyn.h"
#include "dp_nat.h"
#include "dp_vnf.h"
#include "nodes/common_node.h"
#include "rte_flow/dp_rte_flow.h"

#define NEXT_NODES(NEXT) \
	NEXT(IPIP_ENCAP_NEXT_CLS, "cls")
DP_NODE_REGISTER_NOINIT(IPIP_ENCAP, ipip_encap, NEXT_NODES);

static uint16_t next_tx_index[DP_MAX_PORTS];

int ipip_encap_node_append_pf_tx(uint16_t port_id, const char *tx_node_name)
{
	return dp_node_append_pf_tx(DP_NODE_GET_SELF(ipip_encap), next_tx_index, port_id, tx_node_name);
}

static __rte_always_inline rte_edge_t get_next_index(struct rte_node *node, struct rte_mbuf *m)
{
	struct dp_flow *df = dp_get_flow_ptr(m);
	struct rte_ether_hdr *ether_hdr;
	struct rte_ipv4_hdr *ipv4_hdr;
	struct rte_ipv6_hdr *ipv6_hdr;
	rte_be16_t payload_len;
	uint32_t packet_type;
	uint8_t hop_limits;

	if (df->l3_type == RTE_ETHER_TYPE_IPV4) {
		df->tun_info.proto_id = IPPROTO_IPIP;
		ipv4_hdr = dp_get_ipv4_hdr(m);
		hop_limits = ipv4_hdr->time_to_live;
		payload_len = ipv4_hdr->total_length;
		packet_type = RTE_PTYPE_L3_IPV6 | RTE_PTYPE_TUNNEL_IP | RTE_PTYPE_INNER_L3_IPV4 | RTE_PTYPE_L2_ETHER;
	} else if (df->l3_type == RTE_ETHER_TYPE_IPV6) {
		df->tun_info.proto_id = IPPROTO_IPV6;
		ipv6_hdr = dp_get_ipv6_hdr(m);
		hop_limits = ipv6_hdr->hop_limits;
		payload_len = htons(ntohs(ipv6_hdr->payload_len) + sizeof(struct rte_ipv6_hdr));
		packet_type = RTE_PTYPE_L3_IPV6 | RTE_PTYPE_TUNNEL_IP | RTE_PTYPE_INNER_L3_IPV6 | RTE_PTYPE_L2_ETHER;
	} else {
		DPNODE_LOG_WARNING(node, "Invalid tunnel type", DP_LOG_VALUE(df->l3_type));
		return IPIP_ENCAP_NEXT_DROP;
	}

	m->outer_l2_len = sizeof(struct rte_ether_hdr);
	m->outer_l3_len = sizeof(struct rte_ipv6_hdr);
	m->l2_len = 0; /* We dont have inner l2, when we encapsulate */

	rte_pktmbuf_adj(m, sizeof(struct rte_ether_hdr));
	ether_hdr = (struct rte_ether_hdr *)rte_pktmbuf_prepend(m, sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv6_hdr));
	if (unlikely(!ether_hdr)) {
		DPNODE_LOG_WARNING(node, "No space in mbuf for IPv6 header");
		return IPIP_ENCAP_NEXT_DROP;
	}

	dp_fill_ether_hdr(ether_hdr, dp_get_out_port(df), RTE_ETHER_TYPE_IPV6);

	ipv6_hdr = (struct rte_ipv6_hdr *)(ether_hdr + 1);
	ipv6_hdr->hop_limits = hop_limits;
	ipv6_hdr->payload_len = payload_len;
	ipv6_hdr->vtc_flow = htonl(DP_IP6_VTC_FLOW);

	if (df->nat_type == DP_LB_RECIRC)
		// store the original ipv6 dst address in the packet
		dp_set_src_ipv6(ipv6_hdr, &df->tun_info.ul_src_addr6);
	else
		dp_set_src_ipv6(ipv6_hdr, dp_get_port_ul_ipv6(dp_get_in_port(m)));

	dp_set_dst_ipv6(ipv6_hdr, &df->tun_info.ul_dst_addr6);
	ipv6_hdr->proto = df->tun_info.proto_id;

	m->packet_type = packet_type;
	m->ol_flags |= RTE_MBUF_F_TX_OUTER_IPV6;
	m->ol_flags |= RTE_MBUF_F_TX_TUNNEL_IP;

	if (df->nat_type == DP_LB_RECIRC) {
		dp_get_pkt_mark(m)->flags.is_recirc = true;
		return IPIP_ENCAP_NEXT_CLS;
	}

	return next_tx_index[df->nxt_hop];
}

static uint16_t ipip_encap_node_process(struct rte_graph *graph,
										 struct rte_node *node,
										 void **objs,
										 uint16_t nb_objs)
{
	dp_foreach_graph_packet(graph, node, objs, nb_objs, DP_GRAPH_NO_SPECULATED_NODE, get_next_index);
	return nb_objs;
}
