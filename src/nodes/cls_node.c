#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_mbuf.h>
#include "node_api.h"
#include "dp_mbuf_dyn.h"
#include "nodes/ipv6_nd_node.h"

#include "dp_rte_flow.h"

enum
{
	CLS_NEXT_ARP,
	CLS_NEXT_IPV6_ND,
	CLS_NEXT_IPV4_LOOKUP,
	CLS_NEXT_IPV6_LOOKUP,
	CLS_NEXT_OVERLAY_SWITCH,
	CLS_NEXT_DROP,
	CLS_NEXT_MAX
};

static const uint8_t p_nxt[256] __rte_cache_aligned = {
	[RTE_PTYPE_L3_IPV4] = CLS_NEXT_IPV4_LOOKUP,

	[RTE_PTYPE_L3_IPV4_EXT] = CLS_NEXT_IPV4_LOOKUP,

	[RTE_PTYPE_L3_IPV4_EXT_UNKNOWN] = CLS_NEXT_IPV4_LOOKUP,

	[RTE_PTYPE_L3_IPV4 | RTE_PTYPE_L2_ETHER] =
		CLS_NEXT_IPV4_LOOKUP,

	[RTE_PTYPE_L3_IPV4_EXT | RTE_PTYPE_L2_ETHER] =
		CLS_NEXT_IPV4_LOOKUP,

	[RTE_PTYPE_L3_IPV4_EXT_UNKNOWN | RTE_PTYPE_L2_ETHER] =
		CLS_NEXT_IPV4_LOOKUP,
	
	[RTE_PTYPE_L3_IPV6] = CLS_NEXT_IPV6_LOOKUP,

	[RTE_PTYPE_L3_IPV6_EXT] = CLS_NEXT_IPV6_LOOKUP,

	[RTE_PTYPE_L3_IPV6_EXT_UNKNOWN] = CLS_NEXT_IPV6_LOOKUP,

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

static __rte_always_inline int is_arp(struct rte_mbuf *m){
	struct rte_ether_hdr *req_eth_hdr; 
	struct rte_arp_hdr *req_arp_hdr;

	req_eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
	req_arp_hdr = (struct rte_arp_hdr*) (req_eth_hdr + 1);

	// Validate ethernet / IPv4 ARP values are correct
	if (req_arp_hdr->arp_hardware != ntohs(1))
		return 0;
	if (req_arp_hdr->arp_protocol != ntohs(0x0800))
		return 0;
	if (req_arp_hdr->arp_hlen != 6)
		return 0;
	if (req_arp_hdr->arp_plen != 4)
		return 0;

	return 1;
} 

static __rte_always_inline int is_ipv6_nd(struct rte_mbuf *m){
	struct rte_ether_hdr *req_eth_hdr;
	struct rte_ipv6_hdr *req_ipv6_hdr;
	struct icmp6hdr *req_icmp6_hdr;

	req_eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
	if ( req_eth_hdr->ether_type != htons(RTE_ETHER_TYPE_IPV6)) 
		return 0;
	
	req_ipv6_hdr = (struct rte_ipv6_hdr*) (req_eth_hdr + 1);
	if ( req_ipv6_hdr->proto != DP_IP_PROTO_ICMPV6) 
		return 0;

	req_icmp6_hdr = (struct icmp6hdr*) (req_ipv6_hdr + 1);
	uint8_t type = req_icmp6_hdr->icmp6_type ;

	if (type != NDISC_NEIGHBOUR_SOLICITATION && type != NDISC_ROUTER_SOLICITATION)
		return 0;

	return 1;
} 


static __rte_always_inline uint16_t cls_node_process(struct rte_graph *graph,
													 struct rte_node *node,
													 void **objs,
													 uint16_t cnt)
{
	struct rte_mbuf *mbuf0, **pkts;
	rte_edge_t next_index;
	uint8_t comp = 0;
	int i;
	struct dp_flow *df;

	pkts = (struct rte_mbuf **)objs;
	/* Speculative next */
	next_index = CLS_NEXT_DROP;

	for (i = 0; i < cnt; i++) {
		mbuf0 = pkts[i];
		init_dp_mbuf_priv1(mbuf0);
		comp = (mbuf0->packet_type & (RTE_PTYPE_L2_MASK | RTE_PTYPE_L3_MASK));
		/* Mellanox PMD drivers do net set detailed L2 ptype information in mbuf */
		if (comp == RTE_PTYPE_L2_ETHER && is_arp(mbuf0))
			next_index = CLS_NEXT_ARP;
		else if (is_ipv6_nd(mbuf0)) 
			next_index = CLS_NEXT_IPV6_ND;
		else if (p_nxt[comp] == CLS_NEXT_IPV4_LOOKUP) { 
			/* TODO Drop ipv4 packets coming from PF ports */
			extract_inner_ethernet_header(mbuf0);
			next_index = CLS_NEXT_IPV4_LOOKUP;
		} else if (p_nxt[comp] == CLS_NEXT_IPV6_LOOKUP) {
			df = get_dp_flow_ptr(mbuf0);
			if (dp_is_pf_port_id(mbuf0->port)){
				df->flags.flow_type=DP_FLOW_TYPE_INCOMING;
				extract_outter_ethernet_header(mbuf0);
				rte_pktmbuf_adj(mbuf0, (uint16_t)sizeof(struct rte_ether_hdr));
				next_index = CLS_NEXT_OVERLAY_SWITCH;
			}
			else{
				extract_inner_ethernet_header(mbuf0);
				next_index = CLS_NEXT_IPV6_LOOKUP;
			}
		}	
		rte_node_enqueue_x1(graph, node, next_index, mbuf0);
	}	

	return cnt;
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
			[CLS_NEXT_IPV4_LOOKUP] = "conntrack",
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
