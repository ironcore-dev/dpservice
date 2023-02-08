#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_mbuf.h>
#include "node_api.h"
#include "dp_mbuf_dyn.h"
#include "dp_lpm.h"
#include "dp_alias.h"
#include "dpdk_layer.h"
#include "nodes/common_node.h"
#include "nodes/ipip_tunnel_node.h"
#include "rte_flow/dp_rte_flow.h"

struct ipip_tunnel_node_main ipip_tunnel_node;

static int ipip_tunnel_node_init(const struct rte_graph *graph, struct rte_node *node)
{
	struct ipip_tunnel_node_ctx *ctx = (struct ipip_tunnel_node_ctx *)node->ctx;

	ctx->next = IPIP_TUNNEL_NEXT_DROP;

	RTE_SET_USED(graph);

	return 0;
}

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
	uint32_t vni_ns;
	int nxt_hop;

	memcpy(&vni_ns, (df->tun_info.ul_dst_addr6) + 8, 4);
	df->tun_info.dst_vni = ntohl(vni_ns);

	if (df->tun_info.proto_id == DP_IP_PROTO_IPv4_ENCAP)
		next_index = IPIP_TUNNEL_NEXT_IPV4_LOOKUP;

	if (df->tun_info.proto_id == DP_IP_PROTO_IPv6_ENCAP)
		next_index = IPIP_TUNNEL_NEXT_IPV6_LOOKUP;

	nxt_hop = dp_get_portid_with_alias_handle((void *)df->tun_info.ul_dst_addr6);
	if (nxt_hop != -1) {
		df->nxt_hop = nxt_hop;
		/* TODO We jump over the conntrack node, do we need to conntrack alias prefix */
		/* routes ? For example if they have statefull firewall rules ? */
		next_index = IPIP_TUNNEL_NEXT_FIREWALL;
	}

	if (next_index != IPIP_TUNNEL_NEXT_DROP) {
		rte_pktmbuf_adj(m, (uint16_t)sizeof(struct rte_ipv6_hdr));
		m->packet_type &= ~RTE_PTYPE_L3_MASK;
	}

	return next_index;
}

static __rte_always_inline rte_edge_t get_next_index(__rte_unused struct rte_node *node, struct rte_mbuf *m)
{
	struct dp_flow *df = get_dp_flow_ptr(m);

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

int ipip_tunnel_set_next(uint16_t port_id, uint16_t next_index)
{
	ipip_tunnel_node.next_index[port_id] = next_index;
	return 0;
}

static struct rte_node_register ipip_tunnel_node_base = {
	.name = "ipip_tunnel",
	.init = ipip_tunnel_node_init,
	.process = ipip_tunnel_node_process,

	.nb_edges = IPIP_TUNNEL_NEXT_MAX,
	.next_nodes =
		{
			[IPIP_TUNNEL_NEXT_DROP] = "drop",
			[IPIP_TUNNEL_NEXT_IPV6_ENCAP] = "ipv6_encap",
			[IPIP_TUNNEL_NEXT_IPV4_LOOKUP] = "conntrack",
			[IPIP_TUNNEL_NEXT_IPV6_LOOKUP] = "ipv6_lookup",
			[IPIP_TUNNEL_NEXT_FIREWALL] = "firewall",
		},
};

struct rte_node_register *ipip_tunnel_node_get(void)
{
	return &ipip_tunnel_node_base;
}

RTE_NODE_REGISTER(ipip_tunnel_node_base);
