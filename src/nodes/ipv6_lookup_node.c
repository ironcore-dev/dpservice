// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_mbuf.h>
#include "dp_conf.h"
#include "dp_util.h"
#include "dp_error.h"
#include "dp_mbuf_dyn.h"
#include "dp_iface.h"
#include "nodes/common_node.h"
#include "rte_flow/dp_rte_flow.h"

#define NEXT_NODES(NEXT) \
	NEXT(IPV6_LOOKUP_NEXT_SNAT, "snat")
DP_NODE_REGISTER_NOINIT(IPV6_LOOKUP, ipv6_lookup, NEXT_NODES);

static __rte_always_inline rte_edge_t get_next_index(__rte_unused struct rte_node *node, struct rte_mbuf *m)
{
	struct dp_flow *df = dp_get_flow_ptr(m);
	struct rte_ether_hdr *ether_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
	struct dp_iface_route route;
	const struct dp_port *in_port = dp_get_in_port(m);
	const struct dp_port *out_port;
	uint8_t route_key[DP_IPV6_ADDR_SIZE] = {0};  // TODO migrate as separate commit
	uint8_t cmp_key[DP_IPV6_ADDR_SIZE] = {0};  // TODO migrate as separate commit
	int t_vni;

	t_vni = in_port->is_pf ? df->tun_info.dst_vni : 0;

	out_port = dp_get_ip6_out_port(in_port, t_vni, df, &route, route_key);
	if (!out_port)
		return IPV6_LOOKUP_NEXT_DROP;

	if (out_port->is_pf) {
		if (in_port->is_pf)
			return IPV6_LOOKUP_NEXT_DROP;
		dp_copy_ipv6(&df->tun_info.ul_dst_addr6, &route.nh_ipv6);
	} else {
		// next hop is known, fill in Ether header
		// (PF egress goes through a tunnel that destroys Ether header)
		dp_fill_ether_hdr(ether_hdr, out_port, RTE_ETHER_TYPE_IPV6);
	}

	if (!in_port->is_pf)
		df->tun_info.dst_vni = route.vni;

	df->flow_type = rte_rib6_is_equal(route_key, cmp_key) ? DP_FLOW_SOUTH_NORTH : DP_FLOW_WEST_EAST;  // TODO migrate as separate commit
	df->nxt_hop = out_port->port_id;  // always valid since coming from struct dp_port

	return IPV6_LOOKUP_NEXT_SNAT;
}

static uint16_t ipv6_lookup_node_process(struct rte_graph *graph,
										 struct rte_node *node,
										 void **objs,
										 uint16_t nb_objs)
{
	dp_foreach_graph_packet(graph, node, objs, nb_objs, IPV6_LOOKUP_NEXT_SNAT, get_next_index);
	return nb_objs;
}
