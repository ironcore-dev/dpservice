#include <rte_common.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_mbuf.h>
#include "dp_error.h"
#include "dp_lpm.h"
#include "dp_mbuf_dyn.h"
#include "nodes/common_node.h"
#include "rte_flow/dp_rte_flow.h"

// "ipv6_lookup" for unrecognized ipv6 packets, normally it is not needed
#define NEXT_NODES(NEXT) \
	NEXT(OVERLAY_SWITCH_NEXT_IPIP, "ipip_tunnel") \
	NEXT(OVERLAY_SWITCH_NEXT_IPV6_LOOKUP, "ipv6_lookup")
DP_NODE_REGISTER_NOINIT(OVERLAY_SWITCH, overlay_switch, NEXT_NODES);

static __rte_always_inline rte_edge_t get_next_index(__rte_unused struct rte_node *node, struct rte_mbuf *m)
{
	struct dp_flow *df = dp_get_flow_ptr(m);
	struct rte_ipv6_hdr *ipv6_hdr;

	if (df->flags.flow_type == DP_FLOW_TYPE_OUTGOING)
		return OVERLAY_SWITCH_NEXT_IPIP;

	if (df->flags.flow_type == DP_FLOW_TYPE_INCOMING) {
		ipv6_hdr = dp_get_ipv6_hdr(m);
		switch (ipv6_hdr->proto) {
		case DP_IP_PROTO_IPv4_ENCAP:
			df->l3_type = RTE_ETHER_TYPE_IPV4;
			dp_extract_underlay_header(df, ipv6_hdr);
			return OVERLAY_SWITCH_NEXT_IPIP;
		case DP_IP_PROTO_IPv6_ENCAP:
			df->l3_type = RTE_ETHER_TYPE_IPV6;
			dp_extract_underlay_header(df, ipv6_hdr);
			return OVERLAY_SWITCH_NEXT_IPIP;
		default:
			return OVERLAY_SWITCH_NEXT_IPV6_LOOKUP;
		}
	}

	return OVERLAY_SWITCH_NEXT_DROP;
}

static uint16_t overlay_switch_node_process(struct rte_graph *graph,
											struct rte_node *node,
											void **objs,
											uint16_t nb_objs)
{
	dp_foreach_graph_packet(graph, node, objs, nb_objs, OVERLAY_SWITCH_NEXT_IPIP, get_next_index);
	return nb_objs;
}
