#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_graph.h>
#include <rte_arp.h>
#include <rte_graph_worker.h>
#include <rte_mbuf.h>
#include "dp_mbuf_dyn.h"
#include "node_api.h"
#include "nodes/common_node.h"
#include "nodes/ipv6_nd_node.h"

#include "rte_flow/dp_rte_flow.h"

enum
{
	CLS_NEXT_ARP,
	CLS_NEXT_IPV6_ND,
	CLS_NEXT_CONNTRACK,
	CLS_NEXT_IPV6_LOOKUP,
	CLS_NEXT_OVERLAY_SWITCH,
	CLS_NEXT_DROP,
	CLS_NEXT_MAX
};

static const uint8_t next_nodes[256] __rte_cache_aligned = {
	[RTE_PTYPE_L3_IPV4] =
		CLS_NEXT_CONNTRACK,

	[RTE_PTYPE_L3_IPV4_EXT] =
		CLS_NEXT_CONNTRACK,

	[RTE_PTYPE_L3_IPV4_EXT_UNKNOWN] =
		CLS_NEXT_CONNTRACK,

	[RTE_PTYPE_L3_IPV4 | RTE_PTYPE_L2_ETHER] =
		CLS_NEXT_CONNTRACK,

	[RTE_PTYPE_L3_IPV4_EXT | RTE_PTYPE_L2_ETHER] =
		CLS_NEXT_CONNTRACK,

	[RTE_PTYPE_L3_IPV4_EXT_UNKNOWN | RTE_PTYPE_L2_ETHER] =
		CLS_NEXT_CONNTRACK,
	
	[RTE_PTYPE_L3_IPV6] =
		CLS_NEXT_IPV6_LOOKUP,

	[RTE_PTYPE_L3_IPV6_EXT] =
		CLS_NEXT_IPV6_LOOKUP,

	[RTE_PTYPE_L3_IPV6_EXT_UNKNOWN] =
		CLS_NEXT_IPV6_LOOKUP,

	[RTE_PTYPE_L3_IPV6 | RTE_PTYPE_L2_ETHER] =
		CLS_NEXT_IPV6_LOOKUP,

	[RTE_PTYPE_L3_IPV6_EXT | RTE_PTYPE_L2_ETHER] =
		CLS_NEXT_IPV6_LOOKUP,

	[RTE_PTYPE_L3_IPV6_EXT_UNKNOWN | RTE_PTYPE_L2_ETHER] =
		CLS_NEXT_IPV6_LOOKUP,
};

struct cls_node_ctx
{
	uint16_t next;
};

static int cls_node_init(const struct rte_graph *graph, struct rte_node *node)
{
	struct cls_node_ctx *ctx = (struct cls_node_ctx *)node->ctx;

	ctx->next = CLS_NEXT_DROP;

	RTE_SET_USED(graph);

	return 0;
}

static __rte_always_inline int is_arp(struct rte_mbuf *m)
{
	struct rte_ether_hdr *req_eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
	struct rte_arp_hdr *req_arp_hdr = (struct rte_arp_hdr *)(req_eth_hdr + 1);

	return req_arp_hdr->arp_hardware == ntohs(RTE_ARP_HRD_ETHER)
		&& req_arp_hdr->arp_hlen == RTE_ETHER_ADDR_LEN
		&& req_arp_hdr->arp_protocol == ntohs(RTE_ETHER_TYPE_IPV4)
		&& req_arp_hdr->arp_plen == 4
		;
} 

static __rte_always_inline int is_ipv6_nd(struct rte_mbuf *m)
{
	struct rte_ether_hdr *req_eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
	struct rte_ipv6_hdr *req_ipv6_hdr = (struct rte_ipv6_hdr *)(req_eth_hdr + 1);
	struct icmp6hdr *req_icmp6_hdr = (struct icmp6hdr *)(req_ipv6_hdr + 1);

	return req_eth_hdr->ether_type == htons(RTE_ETHER_TYPE_IPV6)
		&& req_ipv6_hdr->proto == DP_IP_PROTO_ICMPV6
		&& (req_icmp6_hdr->icmp6_type == NDISC_NEIGHBOUR_SOLICITATION
			|| req_icmp6_hdr->icmp6_type == NDISC_ROUTER_SOLICITATION)
		;
} 

static __rte_always_inline rte_edge_t get_next_index(__rte_unused struct rte_node *node, struct rte_mbuf *m)
{
	uint8_t pkt_type = (m->packet_type & (RTE_PTYPE_L2_MASK | RTE_PTYPE_L3_MASK));
	struct dp_flow *df;

	init_dp_mbuf_priv1(m);

	/* Mellanox PMD drivers do net set detailed L2 ptype information in mbuf */
	if (pkt_type == RTE_PTYPE_L2_ETHER && is_arp(m))
		return CLS_NEXT_ARP;

	if (is_ipv6_nd(m))
		return CLS_NEXT_IPV6_ND;

	if (next_nodes[pkt_type] == CLS_NEXT_CONNTRACK) {
		/* TODO Drop ipv4 packets coming from PF ports */
		extract_inner_ethernet_header(m);
		return CLS_NEXT_CONNTRACK;
	}

	if (next_nodes[pkt_type] == CLS_NEXT_IPV6_LOOKUP) {
		if (dp_port_is_pf(m->port)) {
			df = get_dp_flow_ptr(m);
			df->flags.flow_type = DP_FLOW_TYPE_INCOMING;
			extract_outter_ethernet_header(m);
			rte_pktmbuf_adj(m, (uint16_t)sizeof(struct rte_ether_hdr));
			m->packet_type &= ~RTE_PTYPE_L2_MASK;
			return CLS_NEXT_OVERLAY_SWITCH;
		} else {
			extract_inner_ethernet_header(m);
			return CLS_NEXT_IPV6_LOOKUP;
		}
	}

	return CLS_NEXT_DROP;
}

static uint16_t cls_node_process(struct rte_graph *graph,
								 struct rte_node *node,
								 void **objs,
								 uint16_t nb_objs)
{
	dp_foreach_graph_packet(graph, node, objs, nb_objs, (int32_t)CLS_NEXT_IPV4_LOOKUP, get_next_index);
	return nb_objs;
}

static struct rte_node_register cls_node_base = {
	.name = "cls",
	.init = cls_node_init,
	.process = cls_node_process,

	.nb_edges = CLS_NEXT_MAX,
	.next_nodes =
		{
			[CLS_NEXT_ARP] = "arp",
			[CLS_NEXT_IPV6_ND] = "ipv6_nd",
			[CLS_NEXT_CONNTRACK] = "conntrack",
			[CLS_NEXT_IPV6_LOOKUP] = "ipv6_lookup",
			[CLS_NEXT_OVERLAY_SWITCH] = "overlay_switch",
			[CLS_NEXT_DROP] = "drop",
		},
};

struct rte_node_register *cls_node_get(void)
{
	return &cls_node_base;
}

RTE_NODE_REGISTER(cls_node_base);
