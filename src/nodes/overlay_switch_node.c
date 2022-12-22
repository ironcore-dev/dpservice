#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_mbuf.h>
#include "node_api.h"
#include "nodes/common_node.h"
#include "nodes/overlay_switch_node.h"
#include "dp_mbuf_dyn.h"
#include "dp_lpm.h"
#include "dp_util.h"
#include "rte_flow/dp_rte_flow.h"

struct overlay_switch_node_main overlay_switch_node;

static int overlay_switch_node_init(const struct rte_graph *graph, struct rte_node *node)
{
	struct overlay_switch_node_ctx *ctx = (struct overlay_switch_node_ctx *)node->ctx;

	ctx->next = OVERLAY_SWITCH_NEXT_DROP;

	RTE_SET_USED(graph);

	return 0;
}

static __rte_always_inline bool is_encaped_geneve_pkt(struct rte_mbuf *m)
{
	struct underlay_conf *u_conf = get_underlay_conf();
	struct rte_udp_hdr *udp_hdr = rte_pktmbuf_mtod_offset(m, struct rte_udp_hdr *,  sizeof(struct rte_ipv6_hdr));

	// ??? is it better to say ntohs(udp_hdr->dst_port) == GENEVE_UDP_PORT?
	return ntohs(udp_hdr->dst_port) == u_conf->src_port;
}

static __rte_always_inline rte_edge_t get_next_index(struct rte_mbuf *m)
{
	struct dp_flow *df = get_dp_flow_ptr(m);
	enum dp_conf_overlay_type overlay_type = dp_conf_get_overlay_type();
	int proto_id;

	if (df->flags.flow_type == DP_FLOW_TYPE_OUTGOING) {
		switch (overlay_type) {
		case DP_CONF_OVERLAY_TYPE_IPIP:
			return OVERLAY_SWITCH_NEXT_IPIP;
		case DP_CONF_OVERLAY_TYPE_GENEVE:
			return OVERLAY_SWITCH_NEXT_GENEVE;
		}
	}

	if (df->flags.flow_type == DP_FLOW_TYPE_INCOMING) {
		proto_id = extract_outer_ipv6_header(m, NULL, 0);
		if (proto_id < 0)
			return OVERLAY_SWITCH_NEXT_DROP;

		if ((proto_id == DP_IP_PROTO_IPv4_ENCAP || proto_id == DP_IP_PROTO_IPv6_ENCAP)
			&& overlay_type == DP_CONF_OVERLAY_TYPE_IPIP
		) {
			df->l3_type = (proto_id == DP_IP_PROTO_IPv4_ENCAP) ? RTE_ETHER_TYPE_IPV4 : RTE_ETHER_TYPE_IPV6;
			return OVERLAY_SWITCH_NEXT_IPIP;
		}

		if (proto_id == DP_IP_PROTO_UDP && is_encaped_geneve_pkt(m)
			&& overlay_type == DP_CONF_OVERLAY_TYPE_GENEVE
		) {
			return OVERLAY_SWITCH_NEXT_GENEVE;
		}

		return OVERLAY_SWITCH_NEXT_IPV6_LOOKUP;
	}

	return OVERLAY_SWITCH_NEXT_DROP;
}

static uint16_t overlay_switch_node_process(struct rte_graph *graph,
											struct rte_node *node,
											void **objs,
											uint16_t nb_objs)
{
	dp_foreach_graph_packet(graph, node, objs, nb_objs, get_next_index);
	return nb_objs;
}

int overlay_switch_set_next(uint16_t port_id, uint16_t next_index)
{
	overlay_switch_node.next_index[port_id] = next_index;
	return 0;
}

static struct rte_node_register overlay_switch_node_base = {
	.name = "overlay_switch",
	.init = overlay_switch_node_init,
	.process = overlay_switch_node_process,

	.nb_edges = OVERLAY_SWITCH_NEXT_MAX,
	.next_nodes =
		{
			[OVERLAY_SWITCH_NEXT_DROP] = "drop",
			[OVERLAY_SWITCH_NEXT_GENEVE] = "geneve_tunnel",
			[OVERLAY_SWITCH_NEXT_IPIP] = "ipip_tunnel",
			[OVERLAY_SWITCH_NEXT_IPV6_LOOKUP] = "ipv6_lookup", // for unrecognized ipv6 packets, normally it is not needed

		},
};

struct rte_node_register *overlay_switch_node_get(void)
{
	return &overlay_switch_node_base;
}

RTE_NODE_REGISTER(overlay_switch_node_base);
