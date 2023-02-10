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

	return req_ipv6_hdr->proto == DP_IP_PROTO_ICMPV6
		&& (req_icmp6_hdr->icmp6_type == NDISC_NEIGHBOUR_SOLICITATION
			|| req_icmp6_hdr->icmp6_type == NDISC_ROUTER_SOLICITATION)
		;
} 

static __rte_always_inline rte_edge_t get_next_index(__rte_unused struct rte_node *node, struct rte_mbuf *m)
{
	uint32_t l2_type = m->packet_type & RTE_PTYPE_L2_MASK;
	uint32_t l3_type = m->packet_type & RTE_PTYPE_L3_MASK;
	struct dp_flow *df = init_dp_flow_ptr(m);

	if (unlikely(l2_type != RTE_PTYPE_L2_ETHER))
		return CLS_NEXT_DROP;

	if (unlikely(l3_type == 0)) {
		// Manual test, because Mellanox PMD drivers do not set detailed L2 packet_type in mbuf
		if (is_arp(m))
			return CLS_NEXT_ARP;
		return CLS_NEXT_DROP;
	}

	if (RTE_ETH_IS_IPV4_HDR(l3_type)) {
		/* TODO Drop ipv4 packets coming from PF ports */
		extract_inner_ethernet_header(m);
		return CLS_NEXT_CONNTRACK;
	}

	if (RTE_ETH_IS_IPV6_HDR(l3_type)) {
		if (dp_port_is_pf(m->port)) {
			if (unlikely(is_ipv6_nd(m)))
				return CLS_NEXT_DROP;
			df->flags.flow_type = DP_FLOW_TYPE_INCOMING;
			extract_outter_ethernet_header(m);
			rte_pktmbuf_adj(m, (uint16_t)sizeof(struct rte_ether_hdr));
			m->packet_type &= ~RTE_PTYPE_L2_MASK;
			return CLS_NEXT_OVERLAY_SWITCH;
		} else {
			if (is_ipv6_nd(m))
				return CLS_NEXT_IPV6_ND;
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
	dp_foreach_graph_packet(graph, node, objs, nb_objs, CLS_NEXT_CONNTRACK, get_next_index);
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
