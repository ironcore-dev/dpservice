// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_graph.h>
#include <rte_arp.h>
#include <rte_graph_worker.h>
#include <rte_mbuf.h>
#include "dp_conf.h"
#include "dp_error.h"
#include "dp_mbuf_dyn.h"
#include "dp_vnf.h"
#include "nodes/cls_node.h"
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

static bool ipsec_enabled = false;

// Connected dynamically, so that a dp-service without IPsec has exactly the graph it had
// before the feature existed - the node does not even become a part of it
static uint16_t next_ipsec_decap_index;

int cls_node_append_ipsec_decap(void)
{
	return dp_node_append_edge(DP_NODE_GET_SELF(cls), &next_ipsec_decap_index, "ipsec_decap");
}

static int cls_node_init(__rte_unused const struct rte_graph *graph, __rte_unused struct rte_node *node)
{
#ifdef ENABLE_VIRTSVC
	virtsvc_present = dp_virtsvc_get_count() > 0;
	virtsvc_ipv4_tree = dp_virtsvc_get_ipv4_tree();
	virtsvc_ipv6_tree = dp_virtsvc_get_ipv6_tree();
#endif
	ipsec_enabled = dp_conf_is_ipsec_enabled();
	return DP_OK;
}

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
	struct dp_port *dst_port;
#ifdef ENABLE_VIRTSVC
	struct dp_virtsvc *virtsvc;
#endif

	if (unlikely((m->packet_type & RTE_PTYPE_L2_MASK) != RTE_PTYPE_L2_ETHER))
		return CLS_NEXT_DROP;

	l3_type = m->packet_type & RTE_PTYPE_L3_MASK;
	ether_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);

	// connected nodes need dp_flow structure (call cannot fail)
	df = dp_init_flow_ptr(m);

	if (unlikely(l3_type == 0)) {
		// Manual test, because Mellanox PMD drivers do not set detailed L2 packet_type in mbuf
		if (is_arp(ether_hdr))
			return CLS_NEXT_ARP;
		return CLS_NEXT_DROP;
	}

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
			// both paths below need these, and so does the endpoint lookup between them
			df->tun_info.l3_type = ntohs(ether_hdr->ether_type);
			dp_extract_underlay_header(df, ipv6_hdr);

			// Encryption is a property of the destination interface, and the frame's
			// protection has to match it: ESP is refused at a cleartext interface, and
			// cleartext at an encrypting one. That is the whole of the inbound policy,
			// and this is the only place it can be applied - the endpoint is not known
			// before it, and after it the distinction is gone, because ipsec_decap
			// deliberately leaves a decrypted frame looking exactly like one that arrived
			// in the clear. See "Why encryption is per interface" in
			// docs/concepts/ipsec.md.
			//
			// Like the VNI check in ipsec_decap this decides on unauthenticated data, and
			// is safe for the same reason: the outcome is always a drop, so a forged frame
			// cannot cause a legitimate one to be discarded. ipip_decap repeats the lookup
			// and gets the cached result, exactly as it already does behind ipsec_decap.
			if (ipsec_enabled) {
				dst_port = dp_vnf_resolve_tunnel_dst(m);
				if (unlikely(!dst_port))
					return CLS_NEXT_DROP;
				if (unlikely(dst_port->iface.encrypt != (ipv6_hdr->proto == IPPROTO_ESP)))
					return CLS_NEXT_DROP;
				if (dst_port->iface.encrypt)
					return next_ipsec_decap_index;
			}

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

static uint16_t cls_node_process(struct rte_graph *graph,
								 struct rte_node *node,
								 void **objs,
								 uint16_t nb_objs)
{
	dp_foreach_graph_packet(graph, node, objs, nb_objs, CLS_NEXT_CONNTRACK, get_next_index);
	return nb_objs;
}
