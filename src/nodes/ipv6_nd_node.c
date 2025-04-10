// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#include "nodes/ipv6_nd_node.h"
#include <rte_common.h>
#include <rte_ether.h>
#include <rte_graph.h>
#include <rte_mbuf.h>
#include "dp_conf.h"
#include "dp_lpm.h"
#include "dp_port.h"
#include "nodes/common_node.h"

DP_NODE_REGISTER_NOINIT(IPV6_ND, ipv6_nd, DP_NODE_DEFAULT_NEXT_ONLY);

static uint16_t next_tx_index[DP_MAX_PORTS];

int ipv6_nd_node_append_vf_tx(uint16_t port_id, const char *tx_node_name)
{
	return dp_node_append_vf_tx(DP_NODE_GET_SELF(ipv6_nd), next_tx_index, port_id, tx_node_name);
}

uint16_t dp_ipv6_fill_ra(struct rte_ipv6_hdr *ipv6_hdr, struct ra_msg *ra_msg, const uint8_t *src_mac_addr)
{
	struct icmp6hdr *icmp6_hdr = &(ra_msg->icmph);
	struct nd_opt_source_link_layer *src_ll_addr;

	memset(icmp6_hdr, 0, sizeof(struct icmp6hdr));
	icmp6_hdr->icmp6_type = NDISC_ROUTER_ADVERTISEMENT;
	icmp6_hdr->icmp6_managed = 1;
	icmp6_hdr->icmp6_other = 1;
	icmp6_hdr->icmp6_rt_lifetime = 0xffff;
	ra_msg->reachable_time = 0;
	ra_msg->retrans_timer = 0;
	icmp6_hdr->icmp6_hop_limit = 255;

	ipv6_hdr->payload_len = htons(sizeof(struct ra_msg) + sizeof(struct nd_opt_source_link_layer));

	src_ll_addr = (struct nd_opt_source_link_layer *)(ra_msg + 1);
	src_ll_addr->type = ND_OPT_SOURCE_LL_ADDR;
	src_ll_addr->length = ND_OPT_LEN_OCTET_1;
	if (src_mac_addr)
		rte_memcpy(src_ll_addr->addr, src_mac_addr, sizeof(src_ll_addr->addr));

	return sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv6_hdr) + sizeof(struct ra_msg)
		   + sizeof(struct nd_opt_source_link_layer);
}

static __rte_always_inline rte_edge_t get_next_index(__rte_unused struct rte_node *node, struct rte_mbuf *m)
{
	struct rte_ether_hdr *req_eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
	struct rte_ipv6_hdr *req_ipv6_hdr = (struct rte_ipv6_hdr *)(req_eth_hdr + 1);
	struct icmp6hdr *req_icmp6_hdr = (struct icmp6hdr *)(req_ipv6_hdr + 1);
	uint8_t icmp_type = req_icmp6_hdr->icmp6_type;
	const union dp_ipv6 *gw_ip = dp_get_gw_ip6();
	struct nd_msg *nd_msg;
	struct ra_msg *req_ra_msg;
	struct dp_port *port = dp_get_in_port(m);
	const union dp_ipv6 *src_ipv6 = dp_get_src_ipv6(req_ipv6_hdr);

	rte_ether_addr_copy(&req_eth_hdr->src_addr, &req_eth_hdr->dst_addr);
	rte_ether_addr_copy(&port->own_mac, &req_eth_hdr->src_addr);

	if (dp_ipv6_match(src_ipv6, &dp_empty_ipv6))
		dp_set_dst_ipv6(req_ipv6_hdr, &dp_multicast_ipv6);
	else
		dp_set_dst_ipv6(req_ipv6_hdr, src_ipv6);

	dp_set_src_ipv6(req_ipv6_hdr, gw_ip);

	if (icmp_type != NDISC_NEIGHBOUR_SOLICITATION && icmp_type != NDISC_ROUTER_SOLICITATION)
		return IPV6_ND_NEXT_DROP;

	if (icmp_type == NDISC_NEIGHBOUR_SOLICITATION) {
		nd_msg = (struct nd_msg *)(req_ipv6_hdr + 1);
		static_assert(sizeof(nd_msg->target) == sizeof(*gw_ip), "Incompatible IPv6 format in ND message structure");
		if (!dp_ipv6_match((const union dp_ipv6 *)nd_msg->target, gw_ip))
			return IPV6_ND_NEXT_DROP;
		rte_ether_addr_copy(&req_eth_hdr->dst_addr, &port->neigh_mac);
		dp_copy_ipv6(&port->iface.cfg.own_ipv6, dp_get_dst_ipv6(req_ipv6_hdr));
		req_icmp6_hdr->icmp6_type = NDISC_NEIGHBOUR_ADVERTISEMENT;
		req_icmp6_hdr->icmp6_solicited = 1;
		req_icmp6_hdr->icmp6_override = 1;
		req_icmp6_hdr->icmp6_router = 1;
		// set target lladdr option and MAC
		nd_msg->opt[0] = ND_OPT_TARGET_LL_ADDR;
		nd_msg->opt[1] = ND_OPT_LEN_OCTET_1;
		rte_ether_addr_copy(&req_eth_hdr->src_addr, (struct rte_ether_addr *)&nd_msg->opt[2]);
	} else if (icmp_type == NDISC_ROUTER_SOLICITATION) {
		req_ra_msg = (struct ra_msg *)(req_ipv6_hdr + 1);
		m->data_len = dp_ipv6_fill_ra(req_ipv6_hdr, req_ra_msg, port->own_mac.addr_bytes);
		m->pkt_len = m->data_len;
	}

	req_icmp6_hdr->icmp6_cksum = 0;
	req_icmp6_hdr->icmp6_cksum = rte_ipv6_udptcp_cksum(req_ipv6_hdr,req_icmp6_hdr);

	return next_tx_index[m->port];
}

static uint16_t ipv6_nd_node_process(struct rte_graph *graph,
									 struct rte_node *node,
									 void **objs,
									 uint16_t nb_objs)
{
	if (dp_conf_is_ipv6_overlay_enabled())
		dp_foreach_graph_packet(graph, node, objs, nb_objs, DP_GRAPH_NO_SPECULATED_NODE, get_next_index);
	else
		dp_forward_graph_packets(graph, node, objs, nb_objs, IPV6_ND_NEXT_DROP);

	return nb_objs;
}
