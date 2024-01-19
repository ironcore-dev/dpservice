// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

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
	NEXT(IPIP_DECAP_NEXT_CONNTRACK, "conntrack")
DP_NODE_REGISTER_NOINIT(IPIP_DECAP, ipip_decap, NEXT_NODES);

static __rte_always_inline rte_edge_t get_next_index(__rte_unused struct rte_node *node, struct rte_mbuf *m)
{
	struct dp_flow *df = dp_get_flow_ptr(m);
	struct rte_ether_hdr *ether_hdr;
	const struct dp_vnf *vnf;
	struct dp_port *dst_port;
	uint32_t l3_type;

	vnf = dp_get_vnf(df->tun_info.ul_dst_addr6);
	if (!vnf)
		return IPIP_DECAP_NEXT_DROP;

	dst_port = dp_get_port_by_id(vnf->port_id);
	if (!dst_port)
		return IPIP_DECAP_NEXT_DROP;

	df->tun_info.dst_vni = vnf->vni;
	df->vnf_type = vnf->type;
	df->nxt_hop = vnf->port_id;  // already validated above

	switch (df->tun_info.proto_id) {
	case IPPROTO_IPIP:
		l3_type = RTE_PTYPE_L3_IPV4;
		break;
	case DP_IP_PROTO_IPv6_ENCAP:
		l3_type = RTE_PTYPE_L3_IPV6;
		break;
	default:
		return IPIP_DECAP_NEXT_DROP;
	}

	rte_pktmbuf_adj(m, sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv6_hdr));
	// no errorchecking as we just created more space than we need ^
	ether_hdr = (struct rte_ether_hdr *)rte_pktmbuf_prepend(m, sizeof(struct rte_ether_hdr));
	dp_fill_ether_hdr(ether_hdr, dst_port, df->l3_type);

	// this shift is non-standard as the actual values of PTYPE should be opaque
	m->packet_type = ((m->packet_type & RTE_PTYPE_INNER_L4_MASK) >> 16) | l3_type | RTE_PTYPE_L2_ETHER;

	return IPIP_DECAP_NEXT_CONNTRACK;
}

static uint16_t ipip_decap_node_process(struct rte_graph *graph,
										 struct rte_node *node,
										 void **objs,
										 uint16_t nb_objs)
{
	dp_foreach_graph_packet(graph, node, objs, nb_objs, IPIP_DECAP_NEXT_CONNTRACK, get_next_index);
	return nb_objs;
}
