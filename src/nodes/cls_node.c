// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#include "nodes/cls_node.h"
#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_graph.h>
#include <rte_arp.h>
#include <rte_graph_worker.h>
#include <rte_mbuf.h>
#include "dp_error.h"
#include "dp_mbuf_dyn.h"
#include "nodes/common_node.h"
#include "nodes/ipv6_nd_node.h"
#include "rte_flow/dp_rte_flow.h"

#ifdef ENABLE_VIRTSVC
#	include "dp_virtsvc.h"
	static bool virtsvc_present = false;
	static const struct dp_virtsvc_lookup_entry *virtsvc_ipv4_tree;
	static const struct dp_virtsvc_lookup_entry *virtsvc_ipv6_tree;
#	define VIRTSVC_NEXT(NEXT) NEXT(CLS_NEXT_VIRTSVC, "virtsvc")
#else
#	define VIRTSVC_NEXT(NEXT)
#endif

#define NEXT_NODES(NEXT) \
	NEXT(CLS_NEXT_ARP, "arp") \
	NEXT(CLS_NEXT_IPV6_ND, "ipv6_nd") \
	NEXT(CLS_NEXT_CONNTRACK, "conntrack") \
	NEXT(CLS_NEXT_IPIP_DECAP, "ipip_decap") \
	VIRTSVC_NEXT(NEXT)

DP_NODE_REGISTER(CLS, cls, NEXT_NODES);

#ifdef ENABLE_PF1_PROXY
static bool pf1_proxy_enabled = false;
static uint16_t pf1_port_id;
static uint16_t pf1_proxy_port_id;
#endif

static int cls_node_init(__rte_unused const struct rte_graph *graph, __rte_unused struct rte_node *node)
{
#ifdef ENABLE_PF1_PROXY
	pf1_proxy_enabled = dp_conf_is_pf1_proxy_enabled();
	pf1_port_id = dp_get_pf1()->port_id;
	pf1_proxy_port_id = dp_get_pf1_proxy()->port_id;
#endif
#ifdef ENABLE_VIRTSVC
	virtsvc_present = dp_virtsvc_get_count() > 0;
	virtsvc_ipv4_tree = dp_virtsvc_get_ipv4_tree();
	virtsvc_ipv6_tree = dp_virtsvc_get_ipv6_tree();
#endif
	return DP_OK;
}

#ifdef ENABLE_PF1_PROXY
static uint16_t next_tx_index[DP_MAX_PORTS];

int cls_node_append_tx(uint16_t port_id, const char *tx_node_name)
{
	return dp_node_append_tx(DP_NODE_GET_SELF(cls), next_tx_index, port_id, tx_node_name);
}
#endif

static __rte_always_inline int is_arp(const struct rte_ether_hdr *ether_hdr)
{
	const struct rte_arp_hdr *arp_hdr = (const struct rte_arp_hdr *)(ether_hdr + 1);

	return arp_hdr->arp_hardware == htons(RTE_ARP_HRD_ETHER)
		&& arp_hdr->arp_hlen == RTE_ETHER_ADDR_LEN
		&& arp_hdr->arp_protocol == htons(RTE_ETHER_TYPE_IPV4)
		&& arp_hdr->arp_plen == 4
		;
}

static __rte_always_inline int is_ipv6_nd(const struct rte_ipv6_hdr *ipv6_hdr)
{
	const struct icmp6hdr *icmp6_hdr = (const struct icmp6hdr *)(ipv6_hdr + 1);

	return ipv6_hdr->proto == IPPROTO_ICMPV6
		&& (icmp6_hdr->icmp6_type == NDISC_NEIGHBOUR_SOLICITATION
			|| icmp6_hdr->icmp6_type == NDISC_ROUTER_SOLICITATION)
		;
}

#ifdef ENABLE_VIRTSVC
static __rte_always_inline struct dp_virtsvc *get_outgoing_virtsvc(const struct rte_ether_hdr *ether_hdr)
{
	const struct rte_ipv4_hdr *ipv4_hdr = (const struct rte_ipv4_hdr *)(ether_hdr + 1);
	rte_be32_t addr = ipv4_hdr->dst_addr;
	uint8_t proto = ipv4_hdr->next_proto_id;
	rte_be16_t port;
	const struct dp_virtsvc_lookup_entry *entry;
	int diff;

	if (proto == IPPROTO_TCP)
		port = ((const struct rte_tcp_hdr *)(ipv4_hdr + 1))->dst_port;
	else if (proto == IPPROTO_UDP)
		port = ((const struct rte_udp_hdr *)(ipv4_hdr + 1))->dst_port;
	else
		return NULL;

	entry = virtsvc_ipv4_tree;
	while (entry) {
		diff = dp_virtsvc_ipv4_cmp(proto, addr, port,
								   entry->virtsvc->proto, entry->virtsvc->virtual_addr, entry->virtsvc->virtual_port);
		if (!diff)
			return entry->virtsvc;
		entry = diff < 0 ? entry->left : entry->right;
	}
	return NULL;
}

static __rte_always_inline struct dp_virtsvc *get_incoming_virtsvc(const struct rte_ipv6_hdr *ipv6_hdr)
{
	const union dp_ipv6 *src_ipv6 = dp_get_src_ipv6(ipv6_hdr);
	uint8_t proto = ipv6_hdr->proto;
	rte_be16_t port;
	const struct dp_virtsvc_lookup_entry *entry;
	int diff;

	if (proto == IPPROTO_TCP)
		port = ((const struct rte_tcp_hdr *)(ipv6_hdr + 1))->src_port;
	else if (proto == IPPROTO_UDP)
		port = ((const struct rte_udp_hdr *)(ipv6_hdr + 1))->src_port;
	else
		return NULL;

	entry = virtsvc_ipv6_tree;
	while (entry) {
		diff = dp_virtsvc_ipv6_cmp(proto, src_ipv6, port,
								   entry->virtsvc->proto, &entry->virtsvc->service_addr, entry->virtsvc->service_port);
		if (!diff)
			return entry->virtsvc;
		entry = diff < 0 ? entry->left : entry->right;
	}
	return NULL;
}
#endif

static __rte_always_inline rte_edge_t get_next_index(__rte_unused struct rte_node *node, struct rte_mbuf *m)
{
	const struct rte_ether_hdr *ether_hdr;
	const struct rte_ipv6_hdr *ipv6_hdr;
	uint32_t l3_type;
	struct dp_flow *df;
	struct dp_port *port;
#ifdef ENABLE_VIRTSVC
	struct dp_virtsvc *virtsvc;
#endif

	if (unlikely((m->packet_type & RTE_PTYPE_L2_MASK) != RTE_PTYPE_L2_ETHER))
		return CLS_NEXT_DROP;

	l3_type = m->packet_type & RTE_PTYPE_L3_MASK;
	ether_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);

	if (unlikely(l3_type == 0)) {
		// Manual test, because Mellanox PMD drivers do not set detailed L2 packet_type in mbuf
		if (is_arp(ether_hdr))
			return CLS_NEXT_ARP;
		return CLS_NEXT_DROP;
	}

	// L3-aware nodes need dp_flow structure (call cannot fail)
	df = dp_init_flow_ptr(m);

	// this is validating the port-id for all subsequent uses of dp_get_port(m)
	port = dp_get_port_by_id(m->port);
	if (unlikely(!port))
		return CLS_NEXT_DROP;

	if (RTE_ETH_IS_IPV4_HDR(l3_type)) {
		if (port->is_pf)
			return CLS_NEXT_DROP;
#ifdef ENABLE_VIRTSVC
		if (virtsvc_present) {
			virtsvc = get_outgoing_virtsvc(ether_hdr);
			if (virtsvc) {
				df->virtsvc = virtsvc;
				return CLS_NEXT_VIRTSVC;
			}
		}
#endif
		df->l3_type = ntohs(ether_hdr->ether_type);
		df->l3_payload_length = rte_pktmbuf_pkt_len(m) - (uint32_t)sizeof(struct rte_ether_hdr);
		return CLS_NEXT_CONNTRACK;
	}

	if (RTE_ETH_IS_IPV6_HDR(l3_type)) {
		ipv6_hdr = (const struct rte_ipv6_hdr *)(ether_hdr + 1);
		if (port->is_pf) {
			if (unlikely(is_ipv6_nd(ipv6_hdr)))
				return CLS_NEXT_DROP;
#ifdef ENABLE_VIRTSVC
			if (virtsvc_present) {
				virtsvc = get_incoming_virtsvc(ipv6_hdr);
				if (virtsvc) {
					df->virtsvc = virtsvc;
					return CLS_NEXT_VIRTSVC;
				}
			}
#endif
			switch (ipv6_hdr->proto) {
			case IPPROTO_IPIP:
				df->l3_type = RTE_ETHER_TYPE_IPV4;
				break;
			case IPPROTO_IPV6:
				df->l3_type = RTE_ETHER_TYPE_IPV6;
				break;
			default:
				return CLS_NEXT_DROP;
			}
			df->tun_info.l3_type = ntohs(ether_hdr->ether_type);
			dp_extract_underlay_header(df, ipv6_hdr);
			return CLS_NEXT_IPIP_DECAP;
		} else {
			if (is_ipv6_nd(ipv6_hdr))
				return CLS_NEXT_IPV6_ND;
			df->l3_type = ntohs(ether_hdr->ether_type);
			return CLS_NEXT_CONNTRACK;
		}
	}

	return CLS_NEXT_DROP;
}

#ifdef ENABLE_PF1_PROXY
static __rte_always_inline rte_edge_t get_next_index_proxy(__rte_unused struct rte_node *node, struct rte_mbuf *m)
{
	rte_edge_t next;

	if (!pf1_proxy_enabled)
		return get_next_index(node, m);

	if (m->port == pf1_proxy_port_id)
		return next_tx_index[pf1_port_id];

	next = get_next_index(node, m);
	if (unlikely(next == CLS_NEXT_DROP && m->port == pf1_port_id))
		return next_tx_index[pf1_proxy_port_id];

	return next;
}
#define get_next_index get_next_index_proxy
#endif

static uint16_t cls_node_process(struct rte_graph *graph,
								 struct rte_node *node,
								 void **objs,
								 uint16_t nb_objs)
{
	dp_foreach_graph_packet(graph, node, objs, nb_objs, CLS_NEXT_CONNTRACK, get_next_index);
	return nb_objs;
}
