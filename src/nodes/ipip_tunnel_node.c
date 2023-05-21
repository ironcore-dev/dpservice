#include <rte_common.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_mbuf.h>
#include "dp_mbuf_dyn.h"
#include "dp_vnf.h"
#include "nodes/common_node.h"
#include "rte_flow/dp_rte_flow.h"

#define NEXT_NODES(NEXT) \
	NEXT(IPIP_TUNNEL_NEXT_IPV6_ENCAP, "ipv6_encap") \
	NEXT(IPIP_TUNNEL_NEXT_IPV4_CONNTRACK, "conntrack") \
	NEXT(IPIP_TUNNEL_NEXT_IPV6_LOOKUP, "ipv6_lookup")
DP_NODE_REGISTER_NOINIT(IPIP_TUNNEL, ipip_tunnel, NEXT_NODES);

static __rte_always_inline rte_edge_t handle_ipip_tunnel_encap(struct rte_mbuf *m, struct dp_flow *df)
{
	if (df->l3_type == RTE_ETHER_TYPE_IPV4)
		df->tun_info.proto_id = DP_IP_PROTO_IPv4_ENCAP;

	if (df->l3_type == RTE_ETHER_TYPE_IPV6)
		df->tun_info.proto_id = DP_IP_PROTO_IPv6_ENCAP;

	return IPIP_TUNNEL_NEXT_IPV6_ENCAP;
}

static __rte_always_inline rte_edge_t handle_ipip_tunnel_decap(struct rte_mbuf *m, struct dp_flow *df)
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

static __rte_always_inline rte_edge_t get_next_index(__rte_unused struct rte_node *node, struct rte_mbuf *m)
{
	struct dp_flow *df = dp_get_flow_ptr(m);

	if (df->flags.flow_type == DP_FLOW_TYPE_OUTGOING)
		return handle_ipip_tunnel_encap(m, df);

	if (df->flags.flow_type == DP_FLOW_TYPE_INCOMING)
		return handle_ipip_tunnel_decap(m, df);

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
