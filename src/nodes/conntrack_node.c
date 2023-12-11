// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#include <rte_common.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_mbuf.h>
#include "dp_conf.h"
#include "dp_error.h"
#include "dp_flow.h"
#include "dp_log.h"
#include "dp_cntrack.h"
#include "dp_lpm.h"
#include "dp_mbuf_dyn.h"
#include "dp_vnf.h"
#include "nodes/common_node.h"
#include "protocols/dp_dhcpv6.h"
#include "nodes/dhcp_node.h"
#include "rte_flow/dp_rte_flow.h"

#define NEXT_NODES(NEXT) \
	NEXT(CONNTRACK_NEXT_LB, "lb") \
	NEXT(CONNTRACK_NEXT_DHCPV6, "dhcpv6") \
	NEXT(CONNTRACK_IPV6_LOOKUP, "ipv6_lookup") \
	NEXT(CONNTRACK_NEXT_DNAT, "dnat") \
	NEXT(CONNTRACK_NEXT_FIREWALL, "firewall")
DP_NODE_REGISTER(CONNTRACK, conntrack, NEXT_NODES);

static int conntrack_node_init(__rte_unused const struct rte_graph *graph, __rte_unused struct rte_node *node)
{
	dp_cntrack_init();
	return DP_OK;
}

static __rte_always_inline rte_edge_t get_next_index(__rte_unused struct rte_node *node, struct rte_mbuf *m)
{
	struct dp_flow *df = dp_get_flow_ptr(m);
	struct rte_ipv6_hdr *ipv6_hdr = dp_get_ipv6_hdr(m);
	struct rte_ipv4_hdr *ipv4_hdr = dp_get_ipv4_hdr(m);

	if (df->l3_type == RTE_ETHER_TYPE_IPV4) {
		dp_extract_ipv4_header(df, ipv4_hdr);
		if (DP_FAILED(dp_extract_l4_header(df, ipv4_hdr + 1)))
			return CONNTRACK_NEXT_DROP;
		if (df->l4_type == DP_IP_PROTO_UDP && df->l4_info.trans_port.dst_port == htons(DP_BOOTP_SRV_PORT))
			return CONNTRACK_NEXT_DNAT;
	} else if (df->l3_type == RTE_ETHER_TYPE_IPV6) {
		dp_extract_ipv6_header(df, ipv6_hdr);
		if (DP_FAILED(dp_extract_l4_header(df, ipv6_hdr + 1)))
			return CONNTRACK_NEXT_DROP;
		if (df->l4_type == DP_IP_PROTO_UDP && df->l4_info.trans_port.dst_port == htons(DHCPV6_SERVER_PORT))
			return CONNTRACK_NEXT_DHCPV6;
	}

	if (!dp_conf_is_conntrack_enabled())
		return CONNTRACK_NEXT_DNAT;

	if (df->l4_type == IPPROTO_TCP
		|| df->l4_type == IPPROTO_UDP
		|| df->l4_type == IPPROTO_ICMP
		|| df->l4_type == IPPROTO_ICMPV6
	) {
		if (DP_FAILED(dp_cntrack_handle(m, df)))
			return CONNTRACK_NEXT_DROP;
	} else {
		return CONNTRACK_NEXT_DROP;
	}

	// VFs packets have no VNF information (no tunnel/underlay)
	if (!dp_get_in_port(m)->is_pf)
		return CONNTRACK_NEXT_DNAT;

	switch (df->vnf_type) {
	case DP_VNF_TYPE_LB:
		return CONNTRACK_NEXT_LB;
	case DP_VNF_TYPE_VIP:
	case DP_VNF_TYPE_NAT:
		return CONNTRACK_NEXT_DNAT;
	case DP_VNF_TYPE_LB_ALIAS_PFX:
	case DP_VNF_TYPE_INTERFACE_IP:
	case DP_VNF_TYPE_ALIAS_PFX:
		return CONNTRACK_NEXT_FIREWALL;
	case DP_VNF_TYPE_UNDEFINED:
		return CONNTRACK_NEXT_DROP;
	}

	return CONNTRACK_NEXT_DROP;
}

static uint16_t conntrack_node_process(struct rte_graph *graph,
									   struct rte_node *node,
									   void **objs,
									   uint16_t nb_objs)
{
	dp_foreach_graph_packet(graph, node, objs, nb_objs, CONNTRACK_NEXT_DNAT, get_next_index);
	return nb_objs;
}
