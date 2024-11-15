// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#include <rte_common.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_mbuf.h>
#include "dp_mbuf_dyn.h"
#include "dp_nat.h"
#include "dp_util.h"
#include "protocols/dp_icmpv6.h"
#include "nodes/common_node.h"
#include "rte_flow/dp_rte_flow.h"

#define NEXT_NODES(NEXT) \
	NEXT(PACKET_RELAY_NEXT_IPIP_ENCAP, "ipip_encap")
DP_NODE_REGISTER_NOINIT(PACKET_RELAY, packet_relay, NEXT_NODES);

static __rte_always_inline rte_edge_t lb_nnat_icmp_reply(struct dp_flow *df, struct rte_mbuf *m)
{
	struct rte_ipv4_hdr *ipv4_hdr = dp_get_ipv4_hdr(m);
	struct rte_icmp_hdr *icmp_hdr = (struct rte_icmp_hdr *)(ipv4_hdr + 1);
	uint32_t temp_ip;
	uint32_t cksum;

	if (icmp_hdr->icmp_type != RTE_IP_ICMP_ECHO_REQUEST)
		DP_RETURN_REF_COUNT_REDUCE_DROP(df->conntrack, PACKET_RELAY_NEXT_DROP);

	// rewrite the packet and send it back
	icmp_hdr->icmp_type = RTE_IP_ICMP_ECHO_REPLY;

	cksum = ~icmp_hdr->icmp_cksum & 0xffff;
	cksum += ~RTE_BE16(RTE_IP_ICMP_ECHO_REQUEST << 8) & 0xffff;
	cksum += RTE_BE16(RTE_IP_ICMP_ECHO_REPLY << 8);
	cksum = (cksum & 0xffff) + (cksum >> 16);
	cksum = (cksum & 0xffff) + (cksum >> 16);
	icmp_hdr->icmp_cksum = (uint16_t)~cksum;

	temp_ip = ipv4_hdr->dst_addr;
	ipv4_hdr->dst_addr = ipv4_hdr->src_addr;
	ipv4_hdr->src_addr = temp_ip;
	df->nxt_hop = m->port;
	dp_nat_chg_ip(df, ipv4_hdr, m);
	dp_copy_ipv6(&df->tun_info.ul_dst_addr6, &df->tun_info.ul_src_addr6);

	return PACKET_RELAY_NEXT_IPIP_ENCAP;
}

static __rte_always_inline rte_edge_t lb_nnat_icmpv6_reply(struct dp_flow *df, struct rte_mbuf *m)
{
	struct rte_ipv6_hdr *ipv6_hdr = dp_get_ipv6_hdr(m);
	struct rte_icmp_hdr *icmp6_hdr = (struct rte_icmp_hdr *)(ipv6_hdr + 1);
	union dp_ipv6 temp_addr;

	if (icmp6_hdr->icmp_type != DP_ICMPV6_ECHO_REQUEST)
		DP_RETURN_REF_COUNT_REDUCE_DROP(df->conntrack, PACKET_RELAY_NEXT_DROP);

	icmp6_hdr->icmp_type = DP_ICMPV6_ECHO_REPLY;

	icmp6_hdr->icmp_cksum = 0;
	icmp6_hdr->icmp_cksum = rte_ipv6_udptcp_cksum(ipv6_hdr, icmp6_hdr);

	dp_copy_ipv6(&temp_addr, dp_get_dst_ipv6(ipv6_hdr));
	dp_set_dst_ipv6(ipv6_hdr, dp_get_src_ipv6(ipv6_hdr));
	dp_set_src_ipv6(ipv6_hdr, &temp_addr);

	df->nxt_hop = m->port;
	dp_copy_ipv6(&df->tun_info.ul_dst_addr6, &df->tun_info.ul_src_addr6);

	return PACKET_RELAY_NEXT_IPIP_ENCAP;
}

static __rte_always_inline rte_edge_t get_next_index(__rte_unused struct rte_node *node, struct rte_mbuf *m)
{
	struct dp_flow *df = dp_get_flow_ptr(m);
	struct flow_value *cntrack = df->conntrack;

	if (!cntrack)
		return PACKET_RELAY_NEXT_DROP;

	if (cntrack->nf_info.nat_type == DP_FLOW_NAT_TYPE_NETWORK_NEIGH) {
		df->nxt_hop = m->port;
		// trick: use src place to store old dst address for offloading
		dp_copy_ipv6(&df->tun_info.ul_src_addr6, &df->tun_info.ul_dst_addr6);
		dp_copy_ipv6(&df->tun_info.ul_dst_addr6, &cntrack->nf_info.underlay_dst);
		return PACKET_RELAY_NEXT_IPIP_ENCAP;
	}

	if (df->l4_type == IPPROTO_ICMP)
		return lb_nnat_icmp_reply(df, m);

	if (df->l4_type == IPPROTO_ICMPV6)
		return lb_nnat_icmpv6_reply(df, m);

	DP_RETURN_REF_COUNT_REDUCE_DROP(df->conntrack, PACKET_RELAY_NEXT_DROP);
}

static uint16_t packet_relay_node_process(struct rte_graph *graph,
										  struct rte_node *node,
										  void **objs,
										  uint16_t nb_objs)
{
	dp_foreach_graph_packet(graph, node, objs, nb_objs, PACKET_RELAY_NEXT_IPIP_ENCAP, get_next_index);
	return nb_objs;
}
