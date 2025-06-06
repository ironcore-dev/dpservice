// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#include <rte_arp.h>
#include "dp_error.h"
#include "dp_log.h"
#include "dp_lpm.h"
#include "dp_mbuf_dyn.h"
#include "dp_periodic_msg.h"
#include "dp_port.h"
#include "dp_iface.h"
#include "nodes/arp_node.h"
#include "nodes/ipv6_nd_node.h"

static const struct rte_ether_addr dp_mc_mac = {
	.addr_bytes = { 0x33, 0x33, 0x00, 0x00, 0x00, 0x01 }
};

static __rte_always_inline bool dp_is_ip_set(struct dp_port *port, uint16_t eth_type)
{
	return (eth_type == RTE_ETHER_TYPE_IPV6 && !dp_is_ipv6_zero(&port->iface.cfg.dhcp_ipv6)) ||
		   (eth_type == RTE_ETHER_TYPE_ARP && port->iface.cfg.own_ip != 0);
}

void send_to_all_vfs(const struct rte_mbuf *pkt, uint16_t eth_type)
{
	struct nd_opt_source_link_layer *src_ll_addr;
	struct dp_flow *df;
	struct rte_ether_hdr *eth_hdr;
	struct rte_arp_hdr *arp_hdr;
	struct dp_dpdk_layer *dp_layer = get_dpdk_layer();
	const struct dp_ports *ports = dp_get_ports();
	struct rte_mbuf *clone_buf;
	struct rte_ipv6_hdr *ipv6_hdr;
	struct ra_msg *ra_msg;
	struct icmp6hdr *icmp6_hdr;
	int ret;

	DP_FOREACH_PORT(ports, port) {
		if (port->is_pf || !port->allocated)
			continue;

		if (!dp_is_ip_set(port, eth_type))
			continue;

		clone_buf = rte_pktmbuf_copy(pkt, dp_layer->rte_mempool, 0, UINT32_MAX);
		if (!clone_buf) {
			DPS_LOG_ERR("Cannot clone periodic packet");
			return;
		}

		clone_buf->port = port->port_id;
		eth_hdr = rte_pktmbuf_mtod(clone_buf, struct rte_ether_hdr *);

		rte_ether_addr_copy(&port->own_mac, &eth_hdr->src_addr);

		if (eth_type == RTE_ETHER_TYPE_ARP) {
			arp_hdr = (struct rte_arp_hdr *)(eth_hdr + 1);
			rte_ether_addr_copy(&port->own_mac, &arp_hdr->arp_data.arp_sha);
			if (dp_arp_cycle_needed(port))
				arp_hdr->arp_data.arp_tip = htonl(port->iface.cfg.own_ip);
		}

		if (eth_type == RTE_ETHER_TYPE_IPV6) {
			ipv6_hdr = (struct rte_ipv6_hdr *)(eth_hdr + 1);
			ra_msg = (struct ra_msg *)(ipv6_hdr + 1);
			icmp6_hdr = &(ra_msg->icmph);
			if (icmp6_hdr->icmp6_type == NDISC_ROUTER_ADVERTISEMENT) {
				src_ll_addr = (struct nd_opt_source_link_layer *)(ra_msg + 1);
				rte_memcpy(src_ll_addr->addr, port->own_mac.addr_bytes, sizeof(src_ll_addr->addr));
				icmp6_hdr->icmp6_cksum = 0;
				icmp6_hdr->icmp6_cksum = rte_ipv6_udptcp_cksum(ipv6_hdr, icmp6_hdr);
			}
		}

		dp_init_pkt_mark(clone_buf);
		df = dp_init_flow_ptr(clone_buf);
		df->l3_type = eth_type;

		ret = rte_ring_sp_enqueue(dp_layer->periodic_msg_queue, clone_buf);
		if (DP_FAILED(ret)) {
			DPS_LOG_WARNING("Cannot enqueue message to a VM", DP_LOG_PORTID(clone_buf->port), DP_LOG_RET(ret));
			rte_pktmbuf_free(clone_buf);
		}
	}
}

void trigger_garp(void)
{
	struct rte_ether_hdr *eth_hdr;
	struct rte_arp_hdr *arp_hdr;
	struct rte_mbuf *pkt;

	pkt = rte_pktmbuf_alloc(get_dpdk_layer()->rte_mempool);
	if (!pkt) {
		DPS_LOG_ERR("GARP packet allocation failed");
		return;
	}

	pkt->packet_type = RTE_PTYPE_L2_ETHER_ARP;
	eth_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
	eth_hdr->ether_type = htons(RTE_ETHER_TYPE_ARP);

	memset(eth_hdr->dst_addr.addr_bytes, 0xff, RTE_ETHER_ADDR_LEN);

	arp_hdr = (struct rte_arp_hdr *)(eth_hdr + 1);
	arp_hdr->arp_opcode = htons(DP_ARP_REQUEST);
	arp_hdr->arp_hardware = htons(DP_ARP_HW_ETH);
	arp_hdr->arp_protocol = htons(RTE_ETHER_TYPE_IPV4);
	arp_hdr->arp_hlen = 6;
	arp_hdr->arp_plen = 4;
	arp_hdr->arp_data.arp_sip = arp_hdr->arp_data.arp_tip = htonl(dp_get_gw_ip4());
	memset(arp_hdr->arp_data.arp_tha.addr_bytes, 0, RTE_ETHER_ADDR_LEN);

	pkt->data_len = sizeof(struct rte_ether_hdr) + sizeof(struct rte_arp_hdr);
	pkt->pkt_len = pkt->data_len;

	send_to_all_vfs(pkt, RTE_ETHER_TYPE_ARP);
	rte_pktmbuf_free(pkt);
}

void trigger_nd_unsol_adv(void)
{
	struct rte_ether_hdr *eth_hdr;
	struct rte_ipv6_hdr *ipv6_hdr;
	struct nd_msg *ns_msg;
	struct icmp6hdr *icmp6_hdr;
	uint16_t pkt_size;
	struct rte_mbuf *pkt;
	const union dp_ipv6 *gw_ip = dp_get_gw_ip6();

	pkt = rte_pktmbuf_alloc(get_dpdk_layer()->rte_mempool);
	if (!pkt) {
		DPS_LOG_ERR("ND-NA packet allocation failed");
		return;
	}

	pkt->packet_type = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6 | RTE_PTYPE_L4_ICMP;
	eth_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
	ipv6_hdr = (struct rte_ipv6_hdr *)(eth_hdr + 1);
	ns_msg = (struct nd_msg *)(ipv6_hdr + 1);

	rte_ether_addr_copy(&dp_mc_mac, &eth_hdr->dst_addr);
	eth_hdr->ether_type = htons(RTE_ETHER_TYPE_IPV6);

	ipv6_hdr->proto = IPPROTO_ICMPV6;
	ipv6_hdr->vtc_flow = htonl(0x60000000);
	ipv6_hdr->hop_limits = 255;
	dp_set_src_ipv6(ipv6_hdr, gw_ip);
	dp_set_dst_ipv6(ipv6_hdr, &dp_multicast_ipv6);
	ipv6_hdr->payload_len = htons(sizeof(struct icmp6hdr) + sizeof(struct in6_addr));

	icmp6_hdr = &(ns_msg->icmph);
	memset(icmp6_hdr, 0, sizeof(struct icmp6hdr));
	icmp6_hdr->icmp6_type = NDISC_NEIGHBOUR_ADVERTISEMENT;
	icmp6_hdr->icmp6_solicited = 0;
	icmp6_hdr->icmp6_override = 1;
	icmp6_hdr->icmp6_router = 1;

	DP_IPV6_TO_ARRAY(gw_ip, ns_msg->target);
	pkt_size = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv6_hdr) +
			   sizeof(struct icmp6hdr) + sizeof(struct in6_addr);
	pkt->data_len = pkt_size;
	pkt->pkt_len = pkt_size;

	// L4 cksum calculation
	icmp6_hdr->icmp6_cksum = 0;
	icmp6_hdr->icmp6_cksum = rte_ipv6_udptcp_cksum(ipv6_hdr, icmp6_hdr);

	send_to_all_vfs(pkt, RTE_ETHER_TYPE_IPV6);
	rte_pktmbuf_free(pkt);
}

void trigger_nd_ra(void)
{
	struct rte_ether_hdr *eth_hdr;
	struct rte_ipv6_hdr *ipv6_hdr;
	struct ra_msg *ra_msg;
	struct rte_mbuf *pkt;
	const union dp_ipv6 *gw_ip = dp_get_gw_ip6();

	pkt = rte_pktmbuf_alloc(get_dpdk_layer()->rte_mempool);
	if (!pkt) {
		DPS_LOG_ERR("ND-RA packet allocation failed");
		return;
	}

	pkt->packet_type = RTE_PTYPE_L2_ETHER | RTE_PTYPE_L3_IPV6 | RTE_PTYPE_L4_ICMP;
	eth_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
	ipv6_hdr = (struct rte_ipv6_hdr *)(eth_hdr + 1);
	ra_msg = (struct ra_msg *)(ipv6_hdr + 1);

	memset(&eth_hdr->src_addr, 0xff, RTE_ETHER_ADDR_LEN);
	rte_ether_addr_copy(&dp_mc_mac, &eth_hdr->dst_addr);
	eth_hdr->ether_type = htons(RTE_ETHER_TYPE_IPV6);

	ipv6_hdr->proto = IPPROTO_ICMPV6;
	ipv6_hdr->vtc_flow = htonl(0x60000000);
	ipv6_hdr->hop_limits = 255;
	dp_set_src_ipv6(ipv6_hdr, gw_ip);
	dp_set_dst_ipv6(ipv6_hdr, &dp_multicast_ipv6);

	pkt->data_len = dp_ipv6_fill_ra(ipv6_hdr, ra_msg, NULL);
	pkt->pkt_len = pkt->data_len;

	send_to_all_vfs(pkt, RTE_ETHER_TYPE_IPV6);
	rte_pktmbuf_free(pkt);
}
