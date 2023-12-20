// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#include <rte_common.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_mbuf.h>
#include "dp_error.h"
#include "dp_flow.h"
#include "dp_log.h"
#include "dp_mbuf_dyn.h"
#include "dp_nat.h"
#include "nodes/common_node.h"
#include "rte_flow/dp_rte_flow.h"
#include "protocols/dp_icmpv6.h"
#include "dp_internal_stats.h"

#define NEXT_NODES(NEXT) \
	NEXT(SNAT_NEXT_FIREWALL, "firewall")
DP_NODE_REGISTER_NOINIT(SNAT, snat, NEXT_NODES);

static __rte_always_inline rte_edge_t get_next_index(__rte_unused struct rte_node *node, struct rte_mbuf *m)
{
	struct dp_flow *df = dp_get_flow_ptr(m);
	struct flow_value *cntrack = df->conntrack;
	struct snat_data *snat_data_p = NULL;
	struct rte_ipv4_hdr *ipv4_hdr;
	struct dp_port *port;
	rte_be32_t dest_ip4;
	uint16_t nat_port;
	uint32_t src_ip;
	uint32_t vni;
	int ret;

	if (!cntrack)
		return SNAT_NEXT_FIREWALL;

	port = dp_get_in_port(m);
	if (DP_FLOW_HAS_NO_FLAGS(cntrack->flow_flags) && df->flow_dir == DP_FLOW_DIR_ORG) {
		vni = port->iface.vni;

		if (df->l3_type == RTE_ETHER_TYPE_IPV4) {
			src_ip = ntohl(df->src.src_addr);
			snat_data_p = dp_get_iface_snat_data(src_ip, vni);
		}

		if (snat_data_p && (snat_data_p->vip_ip != 0 || snat_data_p->nat_ip != 0)
			&& df->flow_type == DP_FLOW_SOUTH_NORTH) {
			ipv4_hdr = dp_get_ipv4_hdr(m);
			// TODO(tao?): in case of both VIP and NAT set, VIP gets written here and immediately overwritten by NAT
			if (snat_data_p->vip_ip != 0) {
				ipv4_hdr->src_addr = htonl(snat_data_p->vip_ip);
				cntrack->nf_info.nat_type = DP_FLOW_NAT_TYPE_VIP;
			}
			if (snat_data_p->nat_ip != 0) {
				ret = dp_allocate_network_snat_port(snat_data_p, df, vni);
				if (DP_FAILED(ret))
					return SNAT_NEXT_DROP;
				nat_port = (uint16_t)ret;
				ipv4_hdr->src_addr = htonl(snat_data_p->nat_ip);

				DP_STATS_NAT_INC_USED_PORT_CNT(port);

				if (df->l4_type == DP_IP_PROTO_ICMP) {
					dp_change_icmp_identifier(m, nat_port);
					cntrack->offload_state.orig = DP_FLOW_OFFLOADED;
					cntrack->offload_state.reply = DP_FLOW_OFFLOADED;
					df->offload_state = DP_FLOW_NON_OFFLOAD;
				} else {
					dp_change_l4_hdr_port(m, DP_L4_PORT_DIR_SRC, nat_port);
				}

				cntrack->nf_info.nat_type = DP_FLOW_NAT_TYPE_NETWORK_LOCAL;
				cntrack->nf_info.vni = vni;
				cntrack->nf_info.l4_type = df->l4_type;
				cntrack->nf_info.icmp_err_ip_cksum = ipv4_hdr->hdr_checksum;
				df->nat_port = nat_port;
			}
			df->nat_type = DP_NAT_CHG_SRC_IP;
			df->nat_addr = ipv4_hdr->src_addr; // nat_addr is the new src_addr in ipv4_hdr
			dp_nat_chg_ip(df, ipv4_hdr, m);

			/* Expect the new destination in this conntrack object */
			cntrack->flow_flags |= DP_FLOW_FLAG_SRC_NAT;
			dp_delete_flow(&cntrack->flow_key[DP_FLOW_DIR_REPLY]);
			cntrack->flow_key[DP_FLOW_DIR_REPLY].l3_dst.ip4 = ntohl(ipv4_hdr->src_addr);
			if (snat_data_p->nat_ip != 0)
				cntrack->flow_key[DP_FLOW_DIR_REPLY].port_dst = df->nat_port;

			if (DP_FAILED(dp_add_flow(&cntrack->flow_key[DP_FLOW_DIR_REPLY], cntrack)))
				return SNAT_NEXT_DROP;
		}

		if (df->l3_type == RTE_ETHER_TYPE_IPV6 && port->iface.nat_ip && dp_is_ip6_in_nat64_range(df->dst.dst_addr6)
		    && df->flow_type == DP_FLOW_SOUTH_NORTH) {
			struct snat_data snat_data = {0};

			snat_data.nat_ip = port->iface.nat_ip;
			snat_data.nat_port_range[0] = port->iface.nat_port_range[0];
			snat_data.nat_port_range[1] = port->iface.nat_port_range[1];
			ret = dp_allocate_network_snat_port(&snat_data, df, vni);
			if (DP_FAILED(ret))
				return SNAT_NEXT_DROP;
			nat_port = (uint16_t)ret;

			DP_STATS_NAT_INC_USED_PORT_CNT(port);

			df->nat_port = nat_port;
			df->nat_type = DP_NAT_64_CHG_SRC_IP;
			df->nat_addr = snat_data.nat_ip;
			if (DP_FAILED(dp_nat_chg_ipv6_to_ipv4_hdr(df, m, snat_data.nat_ip, &dest_ip4))) {
				dp_remove_network_snat_port(cntrack);
				DP_STATS_NAT_DEC_USED_PORT_CNT(port);
				return SNAT_NEXT_DROP;
			}

			if (df->l4_type == IPPROTO_ICMP) {
				dp_change_icmp_identifier(m, nat_port);
				cntrack->offload_state.orig = DP_FLOW_OFFLOADED;
				cntrack->offload_state.reply = DP_FLOW_OFFLOADED;
				df->offload_state = DP_FLOW_NON_OFFLOAD;
				if (cntrack->flow_key[DP_FLOW_DIR_REPLY].src.type_src == DP_ICMPV6_ECHO_REQUEST)
					cntrack->flow_key[DP_FLOW_DIR_REPLY].src.type_src = RTE_IP_ICMP_ECHO_REQUEST;
				else if (cntrack->flow_key[DP_FLOW_DIR_REPLY].src.type_src == DP_ICMPV6_ECHO_REPLY)
					cntrack->flow_key[DP_FLOW_DIR_REPLY].src.type_src = RTE_IP_ICMP_ECHO_REPLY;
				else
					cntrack->flow_key[DP_FLOW_DIR_REPLY].src.type_src = 0;
			} else {
				dp_change_l4_hdr_port(m, DP_L4_PORT_DIR_SRC, nat_port);
			}

			ipv4_hdr = dp_get_ipv4_hdr(m);
			cntrack->nf_info.nat_type = DP_FLOW_NAT_TYPE_NETWORK_LOCAL;
			cntrack->nf_info.vni = vni;
			cntrack->nf_info.l4_type = df->l4_type;
			cntrack->nf_info.icmp_err_ip_cksum = ipv4_hdr->hdr_checksum;

			/* Expect the new destination in this conntrack object */
			cntrack->flow_flags |= DP_FLOW_FLAG_SRC_NAT64;
			dp_delete_flow(&cntrack->flow_key[DP_FLOW_DIR_REPLY]);
			memset(cntrack->flow_key[DP_FLOW_DIR_REPLY].l3_src.ip6, 0, DP_IPV6_ADDR_SIZE);
			memset(cntrack->flow_key[DP_FLOW_DIR_REPLY].l3_dst.ip6, 0, DP_IPV6_ADDR_SIZE);
			cntrack->flow_key[DP_FLOW_DIR_REPLY].l3_src.ip4 = ntohl(dest_ip4);
			cntrack->flow_key[DP_FLOW_DIR_REPLY].l3_dst.ip4 = snat_data.nat_ip;
			cntrack->flow_key[DP_FLOW_DIR_REPLY].port_dst = df->nat_port;
			cntrack->flow_key[DP_FLOW_DIR_REPLY].proto = df->l4_type;
			cntrack->flow_key[DP_FLOW_DIR_REPLY].l3_type = RTE_ETHER_TYPE_IPV4;

			if (DP_FAILED(dp_add_flow(&cntrack->flow_key[DP_FLOW_DIR_REPLY], cntrack)))
				return SNAT_NEXT_DROP;

			return SNAT_NEXT_FIREWALL;
		}
	}

	/* We already know what to do */
	if (DP_FLOW_HAS_FLAG_SRC_NAT(cntrack->flow_flags) && df->flow_dir == DP_FLOW_DIR_ORG) {
		ipv4_hdr = dp_get_ipv4_hdr(m);
		ipv4_hdr->src_addr = htonl(cntrack->flow_key[DP_FLOW_DIR_REPLY].l3_dst.ip4);

		if (cntrack->nf_info.nat_type == DP_FLOW_NAT_TYPE_NETWORK_LOCAL) {
			df->nat_port = cntrack->flow_key[DP_FLOW_DIR_REPLY].port_dst;
			if (df->l4_type == DP_IP_PROTO_ICMP)
				dp_change_icmp_identifier(m, cntrack->flow_key[DP_FLOW_DIR_REPLY].port_dst);
			else
				dp_change_l4_hdr_port(m, DP_L4_PORT_DIR_SRC, cntrack->flow_key[DP_FLOW_DIR_REPLY].port_dst);
		}

		df->nat_type = DP_NAT_CHG_SRC_IP;
		df->nat_addr = ipv4_hdr->src_addr;
		dp_nat_chg_ip(df, ipv4_hdr, m);
	}

	if ((DP_FLOW_HAS_FLAG_DST_NAT(cntrack->flow_flags) || DP_FLOW_HAS_FLAG_DST_LB(cntrack->flow_flags))
		&& (df->flow_dir == DP_FLOW_DIR_REPLY)) {
		ipv4_hdr = dp_get_ipv4_hdr(m);
		df->src.src_addr = ipv4_hdr->src_addr;
		ipv4_hdr->src_addr = htonl(cntrack->flow_key[DP_FLOW_DIR_ORG].l3_dst.ip4);
		df->nat_addr = ipv4_hdr->src_addr;
		df->nat_type = DP_NAT_CHG_SRC_IP;
		dp_nat_chg_ip(df, ipv4_hdr, m);
	}

	if (DP_FLOW_HAS_FLAG_SRC_NAT64(cntrack->flow_flags) && df->flow_dir == DP_FLOW_DIR_ORG) {
		if (DP_FAILED(dp_nat_chg_ipv6_to_ipv4_hdr(df, m, port->iface.nat_ip, &dest_ip4)))
			return SNAT_NEXT_DROP;

		if (cntrack->nf_info.nat_type == DP_FLOW_NAT_TYPE_NETWORK_LOCAL) {
			df->nat_port = cntrack->flow_key[DP_FLOW_DIR_REPLY].port_dst;
			if (df->l4_type == IPPROTO_ICMP)
				dp_change_icmp_identifier(m, cntrack->flow_key[DP_FLOW_DIR_REPLY].port_dst);
			else
				dp_change_l4_hdr_port(m, DP_L4_PORT_DIR_SRC, cntrack->flow_key[DP_FLOW_DIR_REPLY].port_dst);
		}

		df->nat_type = DP_NAT_64_CHG_SRC_IP;
		df->nat_addr = port->iface.nat_ip;
	}

	return SNAT_NEXT_FIREWALL;
}

static uint16_t snat_node_process(struct rte_graph *graph,
								  struct rte_node *node,
								  void **objs,
								  uint16_t nb_objs)
{
	dp_foreach_graph_packet(graph, node, objs, nb_objs, SNAT_NEXT_FIREWALL, get_next_index);
	return nb_objs;
}
