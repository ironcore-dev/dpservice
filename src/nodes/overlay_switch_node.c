#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_mbuf.h>
#include "node_api.h"
#include "nodes/overlay_switch_node.h"
#include "dp_mbuf_dyn.h"
#include "dp_lpm.h"
#include "dp_util.h"
#include "dp_rte_flow.h"

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

	struct rte_udp_hdr *udp_hdr;
	struct underlay_conf *u_conf;

	u_conf = get_underlay_conf();
	udp_hdr = rte_pktmbuf_mtod_offset(m, struct rte_udp_hdr *,
									  sizeof(struct rte_ipv6_hdr));

	// 	// ??? is it better to say ntohs(udp_hdr->dst_port) == GENEVE_UDP_PORT?
	return ntohs(udp_hdr->dst_port) == u_conf->src_port;
}

static __rte_always_inline int handle_overlay_switch(struct rte_mbuf *m)
{
	struct dp_flow *df;
	uint16_t ret = OVERLAY_SWITCH_NEXT_DROP;
	int proto_id = -1;

	df = get_dp_flow_ptr(m);

	if (df->flags.flow_type == DP_FLOW_TYPE_OUTGOING)
	{
		if (get_overlay_type() == DP_FLOW_OVERLAY_TYPE_IPIP)
		{
			ret = OVERLAY_SWITCH_NEXT_IPIP;
			return ret;
		}

		if (get_overlay_type() == DP_FLOW_OVERLAY_TYPE_GENEVE)
		{
			ret = OVERLAY_SWITCH_NEXT_GENEVE;
			return ret;
		}
	}

	if (df->flags.flow_type == DP_FLOW_TYPE_INCOMING)
	{

		proto_id = extract_outer_ipv6_header(m, NULL, 0);
		if (proto_id < 0)
			return ret;

		if ((proto_id == DP_IP_PROTO_IPv4_ENCAP || proto_id == DP_IP_PROTO_IPv6_ENCAP) && get_overlay_type() == DP_FLOW_OVERLAY_TYPE_IPIP)
		{
			ret = OVERLAY_SWITCH_NEXT_IPIP;
			df->l3_type = (proto_id == DP_IP_PROTO_IPv4_ENCAP) ? RTE_ETHER_TYPE_IPV4 : RTE_ETHER_TYPE_IPV6;
			return ret;
		}

		if (proto_id == DP_IP_PROTO_UDP && is_encaped_geneve_pkt(m) && get_overlay_type() == DP_FLOW_OVERLAY_TYPE_GENEVE)
		{
			ret = OVERLAY_SWITCH_NEXT_GENEVE;
			return ret;
		}

		ret = OVERLAY_SWITCH_NEXT_IPV6_LOOKUP;
	}

	return ret;
}

static __rte_always_inline uint16_t overlay_switch_node_process(struct rte_graph *graph,
																struct rte_node *node,
																void **objs,
																uint16_t cnt)
{
	struct rte_mbuf *mbuf0, **pkts;
	int i, ret;

	// struct dp_flow *df;

	pkts = (struct rte_mbuf **)objs;

	for (i = 0; i < cnt; i++)
	{
		mbuf0 = pkts[i];
		ret = handle_overlay_switch(mbuf0);

		rte_node_enqueue_x1(graph, node, ret, mbuf0);
	}

	return cnt;
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
