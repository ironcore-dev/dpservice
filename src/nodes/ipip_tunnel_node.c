#include "nodes/ipip_tunnel_node.h"
#include <rte_common.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_mbuf.h>
#include "dp_mbuf_dyn.h"
#include "dp_nat.h"
#include "dp_vnf.h"
#include "nodes/common_node.h"
#include "rte_flow/dp_rte_flow.h"

#define NEXT_NODES(NEXT) \
	NEXT(IPIP_TUNNEL_NEXT_CLS, "cls") \
	NEXT(IPIP_TUNNEL_NEXT_IPV4_CONNTRACK, "conntrack") \
	NEXT(IPIP_TUNNEL_NEXT_IPV6_LOOKUP, "ipv6_lookup")
DP_NODE_REGISTER(IPIP_TUNNEL, ipip_tunnel, NEXT_NODES);

static uint16_t next_tx_index[DP_MAX_PORTS];

int ipip_tunnel_node_append_pf_tx(uint16_t port_id, const char *tx_node_name)
{
	return dp_node_append_pf_tx(DP_NODE_GET_SELF(ipip_tunnel), next_tx_index, port_id, tx_node_name);
}

// runtime constant, precompute
static struct underlay_conf *u_conf;

static int ipip_tunnel_node_init(__rte_unused const struct rte_graph *graph, __rte_unused struct rte_node *node)
{
	u_conf = get_underlay_conf();
	return DP_OK;
}

static __rte_always_inline rte_edge_t handle_ipip_tunnel_encap(struct rte_node *node, struct rte_mbuf *m, struct dp_flow *df)
{
	struct rte_ipv6_hdr *ipv6_hdr;
	rte_be16_t payload_len;
	uint32_t packet_type;

	if (df->l3_type == RTE_ETHER_TYPE_IPV4) {
		df->tun_info.proto_id = DP_IP_PROTO_IPv4_ENCAP;
		payload_len = rte_pktmbuf_mtod(m, struct rte_ipv4_hdr *)->total_length;
		packet_type = RTE_PTYPE_L3_IPV6 | RTE_PTYPE_TUNNEL_IP | RTE_PTYPE_INNER_L3_IPV4;
	} else if (df->l3_type == RTE_ETHER_TYPE_IPV6) {
		df->tun_info.proto_id = DP_IP_PROTO_IPv6_ENCAP;
		payload_len = htons(ntohs(rte_pktmbuf_mtod(m, struct rte_ipv6_hdr *)->payload_len) + sizeof(struct rte_ipv6_hdr));
		packet_type = RTE_PTYPE_L3_IPV6 | RTE_PTYPE_TUNNEL_IP | RTE_PTYPE_INNER_L3_IPV6;
	} else {
		DPNODE_LOG_WARNING(node, "Invalid tunnel type", DP_LOG_VALUE(df->l3_type));
		return IPIP_TUNNEL_NEXT_DROP;
	}

	m->outer_l2_len = sizeof(struct rte_ether_hdr);
	m->outer_l3_len = sizeof(struct rte_ipv6_hdr);
	m->l2_len = 0; /* We dont have inner l2, when we encapsulate */

	ipv6_hdr = (struct rte_ipv6_hdr *)rte_pktmbuf_prepend(m, sizeof(struct rte_ipv6_hdr));
	if (unlikely(!ipv6_hdr)) {
		DPNODE_LOG_WARNING(node, "No space in mbuf for IPv6 header");
		return IPIP_TUNNEL_NEXT_DROP;
	}

	ipv6_hdr->hop_limits = DP_IP6_HOP_LIMIT;
	ipv6_hdr->payload_len = payload_len;
	ipv6_hdr->vtc_flow = htonl(DP_IP6_VTC_FLOW);

	if (df->flags.nat == DP_LB_RECIRC)
		// store the original ipv6 dst address in the packet
		rte_memcpy(ipv6_hdr->src_addr, df->tun_info.ul_src_addr6, sizeof(ipv6_hdr->src_addr));
	else
		rte_memcpy(ipv6_hdr->src_addr, dp_get_vm_ul_ip6(m->port), sizeof(ipv6_hdr->src_addr));

	rte_memcpy(ipv6_hdr->dst_addr, df->tun_info.ul_dst_addr6, sizeof(ipv6_hdr->dst_addr));
	ipv6_hdr->proto = df->tun_info.proto_id;

	m->packet_type = packet_type;
	m->ol_flags |= RTE_MBUF_F_TX_OUTER_IPV6;
	m->ol_flags |= RTE_MBUF_F_TX_TUNNEL_IP;

	if (df->flags.nat == DP_LB_RECIRC) {
		if (unlikely(DP_FAILED(rewrite_eth_hdr(m, df->nxt_hop, RTE_ETHER_TYPE_IPV6)))) {
			DPNODE_LOG_WARNING(node, "No space in mbuf for ethernet header");
			return IPIP_TUNNEL_NEXT_DROP;
		}
		dp_get_pkt_mark(m)->flags.is_recirc = true;
		return IPIP_TUNNEL_NEXT_CLS;
	}

	return next_tx_index[df->nxt_hop];
}

static __rte_always_inline rte_edge_t handle_ipip_tunnel_decap(__rte_unused struct rte_node *node,
															   struct rte_mbuf *m, struct dp_flow *df)
{
	rte_edge_t next_index = IPIP_TUNNEL_NEXT_DROP;
	struct dp_vnf_value *vnf_val;
	uint8_t proto = df->tun_info.proto_id;

	vnf_val = dp_get_vnf_value_with_key((void *)df->tun_info.ul_dst_addr6);
	if (vnf_val) {
		df->tun_info.dst_vni = vnf_val->vni;
		df->vnf_type = vnf_val->v_type;
		df->nxt_hop = vnf_val->portid;
	} else {
		return IPIP_TUNNEL_NEXT_DROP;
	}

	if (proto == DP_IP_PROTO_IPv4_ENCAP)
		next_index = IPIP_TUNNEL_NEXT_IPV4_CONNTRACK;

	if (proto == DP_IP_PROTO_IPv6_ENCAP)
		next_index = IPIP_TUNNEL_NEXT_IPV6_LOOKUP;

	if (next_index != IPIP_TUNNEL_NEXT_DROP) {
		rte_pktmbuf_adj(m, (uint16_t)sizeof(struct rte_ipv6_hdr));
		// this shift is non-standard as the actual values of PTYPE should be opaque
		m->packet_type = ((m->packet_type & RTE_PTYPE_INNER_L4_MASK) >> 16)
						 | (proto == DP_IP_PROTO_IPv4_ENCAP ? RTE_PTYPE_L3_IPV4 : RTE_PTYPE_L3_IPV6);
	}

	return next_index;
}

static __rte_always_inline rte_edge_t get_next_index(struct rte_node *node, struct rte_mbuf *m)
{
	struct dp_flow *df = dp_get_flow_ptr(m);

	if (df->flags.flow_type == DP_FLOW_TYPE_OUTGOING)
		return handle_ipip_tunnel_encap(node, m, df);

	if (df->flags.flow_type == DP_FLOW_TYPE_INCOMING)
		return handle_ipip_tunnel_decap(node, m, df);

	return IPIP_TUNNEL_NEXT_DROP;
}

static uint16_t ipip_tunnel_node_process(struct rte_graph *graph,
										 struct rte_node *node,
										 void **objs,
										 uint16_t nb_objs)
{
	dp_foreach_graph_packet(graph, node, objs, nb_objs, DP_GRAPH_NO_SPECULATED_NODE, get_next_index);
	return nb_objs;
}
