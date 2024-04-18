// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#include <rte_common.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_mbuf.h>
#include "dp_flow.h"
#include "dp_log.h"
#include "dp_lpm.h"
#include "dp_mbuf_dyn.h"
#include "dp_nat.h"
#include "nodes/common_node.h"
#include "protocols/dp_icmpv6.h"
#include "rte_flow/dp_rte_flow.h"

#define NEXT_NODES(NEXT) \
	NEXT(DNAT_NEXT_IPV4_LOOKUP, "ipv4_lookup") \
	NEXT(DNAT_NEXT_IPV6_LOOKUP, "ipv6_lookup") \
	NEXT(DNAT_NEXT_PACKET_RELAY, "packet_relay")
DP_NODE_REGISTER_NOINIT(DNAT, dnat, NEXT_NODES);

static __rte_always_inline rte_edge_t get_next_index(__rte_unused struct rte_node *node, struct rte_mbuf *m)
{
	struct dp_flow *df = dp_get_flow_ptr(m);
	struct flow_value *cntrack = df->conntrack;
	struct rte_ipv4_hdr *ipv4_hdr;
	uint32_t dst_ip, vni;
	const uint8_t *underlay_dst;
	struct dp_icmp_err_ip_info icmp_err_ip_info;
	struct dnat_data *dnat_data;

	if (!cntrack)
		goto out;

	if (DP_FLOW_HAS_NO_FLAGS(cntrack->flow_flags) && df->flow_dir == DP_FLOW_DIR_ORG && df->l3_type == RTE_ETHER_TYPE_IPV4) {
		dst_ip = ntohl(df->dst.dst_addr);
		vni = df->tun_info.dst_vni;
		if (vni == 0)
			vni = dp_get_in_port(m)->iface.vni;

		dnat_data = dp_get_dnat_data(dst_ip, vni);
		if (dnat_data) {
			// if it is a network nat pkt
			if (dnat_data->dnat_ip == 0) {
				// it is icmp request targeting scalable nat
				if (df->l4_type == IPPROTO_ICMP && df->l4_info.icmp_field.icmp_type == RTE_IP_ICMP_ECHO_REQUEST) {
					cntrack->nf_info.nat_type = DP_FLOW_NAT_AS_TARGET;
					return DNAT_NEXT_PACKET_RELAY;
				}

				// only perform this lookup on unknown dnat (Distributed NAted) traffic flows
				underlay_dst = dp_lookup_network_nat_underlay_ip(df);
				if (underlay_dst) {
					cntrack->nf_info.nat_type = DP_FLOW_NAT_TYPE_NETWORK_NEIGH;
					df->nat_type = DP_CHG_UL_DST_IP;
					cntrack->nf_info.l4_type = df->l4_type;
					memcpy(cntrack->nf_info.underlay_dst, underlay_dst, sizeof(cntrack->nf_info.underlay_dst));

					dp_delete_flow(&cntrack->flow_key[DP_FLOW_DIR_REPLY]); // no reverse traffic for relaying pkts
					return DNAT_NEXT_PACKET_RELAY;
				}

				// if it is not a nat pkt destinated for its neighboring nat,
				// then it is a premature dnat pkt for network nat (sent before any outgoing traffic from VM,
				// and it cannot be a standalone new incoming flow for network NAT),
				// silently drop it now.
				return DNAT_NEXT_DROP;
			}

			ipv4_hdr = dp_get_ipv4_hdr(m);
			ipv4_hdr->dst_addr = htonl(dnat_data->dnat_ip);

			df->nat_type = DP_NAT_CHG_DST_IP;
			df->nat_addr = df->dst.dst_addr;
			df->dst.dst_addr = ipv4_hdr->dst_addr;
			dp_nat_chg_ip(df, ipv4_hdr, m);

			/* Expect the new source in this conntrack object */
			cntrack->flow_flags |= DP_FLOW_FLAG_DST_NAT;
			dp_delete_flow(&cntrack->flow_key[DP_FLOW_DIR_REPLY]);
			DP_SET_IPADDR4(cntrack->flow_key[DP_FLOW_DIR_REPLY].l3_src, ntohl(ipv4_hdr->dst_addr));
			if (DP_FAILED(dp_add_flow(&cntrack->flow_key[DP_FLOW_DIR_REPLY], cntrack)))
				return DNAT_NEXT_DROP;
		}
		return DNAT_NEXT_IPV4_LOOKUP;
	}

	if (cntrack->nf_info.nat_type == DP_FLOW_NAT_TYPE_NETWORK_NEIGH) {
		df->nat_type = DP_CHG_UL_DST_IP;
		return DNAT_NEXT_PACKET_RELAY;
	}

	if (DP_FLOW_HAS_FLAG_DEFAULT(cntrack->flow_flags) && cntrack->nf_info.nat_type == DP_FLOW_NAT_AS_TARGET
		&& (df->l4_type == IPPROTO_ICMP || df->l4_type == IPPROTO_ICMPV6)
		&& (df->l4_info.icmp_field.icmp_type == RTE_IP_ICMP_ECHO_REQUEST || df->l4_info.icmp_field.icmp_type == DP_ICMPV6_ECHO_REQUEST))
		return DNAT_NEXT_PACKET_RELAY;

	if (DP_FLOW_HAS_FLAG_DST_NAT(cntrack->flow_flags) && df->flow_dir == DP_FLOW_DIR_ORG) {
		if (cntrack->flow_key[DP_FLOW_DIR_REPLY].l3_src.is_v6)
			return DNAT_NEXT_DROP;
		ipv4_hdr = dp_get_ipv4_hdr(m);
		ipv4_hdr->dst_addr = htonl(cntrack->flow_key[DP_FLOW_DIR_REPLY].l3_src.ipv4);
		df->nat_type = DP_NAT_CHG_DST_IP;
		df->nat_addr = df->dst.dst_addr;
		df->dst.dst_addr = ipv4_hdr->dst_addr;
		dp_nat_chg_ip(df, ipv4_hdr, m);
	}

	/* We already know what to do */
	if (DP_FLOW_HAS_FLAG_SRC_NAT(cntrack->flow_flags) && df->flow_dir == DP_FLOW_DIR_REPLY) {
		if (cntrack->flow_key[DP_FLOW_DIR_ORG].l3_src.is_v6)
			return DNAT_NEXT_DROP;
		ipv4_hdr = dp_get_ipv4_hdr(m);
		ipv4_hdr->dst_addr = htonl(cntrack->flow_key[DP_FLOW_DIR_ORG].l3_src.ipv4);
		if (cntrack->nf_info.nat_type == DP_FLOW_NAT_TYPE_NETWORK_LOCAL) {
			if (df->l4_type == IPPROTO_ICMP) {
				if (df->l4_info.icmp_field.icmp_type == RTE_IP_ICMP_ECHO_REPLY) {
					dp_change_icmp_identifier(m, cntrack->flow_key[DP_FLOW_DIR_ORG].port_dst);
				} else if (df->l4_info.icmp_field.icmp_type == DP_IP_ICMP_TYPE_ERROR) {
					memset(&icmp_err_ip_info, 0, sizeof(icmp_err_ip_info));
					dp_get_icmp_err_ip_hdr(m, &icmp_err_ip_info);
					if (!icmp_err_ip_info.err_ipv4_hdr || !icmp_err_ip_info.l4_src_port || !icmp_err_ip_info.l4_dst_port)
						return DNAT_NEXT_DROP;
					icmp_err_ip_info.err_ipv4_hdr->src_addr = htonl(cntrack->flow_key[DP_FLOW_DIR_ORG].l3_src.ipv4);
					icmp_err_ip_info.err_ipv4_hdr->hdr_checksum = cntrack->nf_info.icmp_err_ip_cksum;
					dp_change_icmp_err_l4_src_port(m, &icmp_err_ip_info, cntrack->flow_key[DP_FLOW_DIR_ORG].src.port_src);
				}
			} else {
				dp_change_l4_hdr_port(m, DP_L4_PORT_DIR_DST, cntrack->flow_key[DP_FLOW_DIR_ORG].src.port_src);
			}
		}
		df->nat_type = DP_NAT_CHG_DST_IP;
		df->nat_addr = df->dst.dst_addr; // record nat IP
		df->dst.dst_addr = ipv4_hdr->dst_addr; // store new dst_addr (which is VM's IP)
		dp_nat_chg_ip(df, ipv4_hdr, m);
	}

	if (DP_FLOW_HAS_FLAG_SRC_NAT64(cntrack->flow_flags) && df->flow_dir == DP_FLOW_DIR_REPLY) {
		df->nat_type = DP_NAT_64_CHG_DST_IP;
		df->nat_addr = df->dst.dst_addr;
		// the new dst_addr will be stored in dp_nat_chg_ipv4_to_ipv6_hdr()
		if (cntrack->nf_info.nat_type == DP_FLOW_NAT_TYPE_NETWORK_LOCAL) {
			if (df->l4_type == IPPROTO_ICMP) {
				if (df->l4_info.icmp_field.icmp_type == RTE_IP_ICMP_ECHO_REPLY)
					dp_change_icmp_identifier(m, cntrack->flow_key[DP_FLOW_DIR_ORG].port_dst);
			} else {
				dp_change_l4_hdr_port(m, DP_L4_PORT_DIR_DST, cntrack->flow_key[DP_FLOW_DIR_ORG].src.port_src);
			}
		}
		if (!cntrack->flow_key[DP_FLOW_DIR_ORG].l3_src.is_v6
			|| DP_FAILED(dp_nat_chg_ipv4_to_ipv6_hdr(df, m, cntrack->flow_key[DP_FLOW_DIR_ORG].l3_src.ipv6)))
			return DNAT_NEXT_DROP;

		return DNAT_NEXT_IPV6_LOOKUP;
	}

out:
	if (df->l3_type == RTE_ETHER_TYPE_IPV4)
		return DNAT_NEXT_IPV4_LOOKUP;
	else if (df->l3_type == RTE_ETHER_TYPE_IPV6)
		return DNAT_NEXT_IPV6_LOOKUP;
	else
		return DNAT_NEXT_DROP;
}

static uint16_t dnat_node_process(struct rte_graph *graph,
								  struct rte_node *node,
								  void **objs,
								  uint16_t nb_objs)
{
	dp_foreach_graph_packet(graph, node, objs, nb_objs, DNAT_NEXT_IPV4_LOOKUP, get_next_index);
	return nb_objs;
}
