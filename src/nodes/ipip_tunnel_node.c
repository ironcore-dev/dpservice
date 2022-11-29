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
#include "dp_debug.h"

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

static __rte_always_inline int handle_ipip_tunnel_encap(struct rte_mbuf *m, struct dp_flow *df)
{
	uint8_t route = IPIP_TUNNEL_NEXT_DROP;

	if (df->l3_type == RTE_ETHER_TYPE_IPV4)
		df->tun_info.proto_id = DP_IP_PROTO_IPv4_ENCAP;

	if (df->l3_type == RTE_ETHER_TYPE_IPV6)
		df->tun_info.proto_id = DP_IP_PROTO_IPv6_ENCAP;

	route = IPIP_TUNNEL_NEXT_IPV6_ENCAP;
	return route;
}

static __rte_always_inline int handle_ipip_tunnel_decap(struct rte_mbuf *m, struct dp_flow *df)
{
	uint8_t route = IPIP_TUNNEL_NEXT_DROP;
	uint32_t vni_ns;
	int nxt_hop;

	memcpy(&vni_ns, (df->tun_info.ul_dst_addr6) + 8, 4);
	df->tun_info.dst_vni = ntohl(vni_ns);

	if (df->tun_info.proto_id == DP_IP_PROTO_IPv4_ENCAP)
		route = IPIP_TUNNEL_NEXT_IPV4_LOOKUP;

	if (df->tun_info.proto_id == DP_IP_PROTO_IPv6_ENCAP)
		route = IPIP_TUNNEL_NEXT_IPV6_LOOKUP;

	nxt_hop = dp_get_portid_with_alias_handle((void *)df->tun_info.ul_dst_addr6);
	if (nxt_hop != -1) {
		/* TODO We jump over the conntrack node, do we need to conntrack alias prefix */
		/* routes ? For example if they have statefull firewall rules ? */
		route = IPIP_TUNNEL_NEXT_FIREWALL;
		df->nxt_hop = nxt_hop;
	}

	if (route != IPIP_TUNNEL_NEXT_DROP)
		rte_pktmbuf_adj(m, (uint16_t)sizeof(struct rte_ipv6_hdr));

	return route;
}

static __rte_always_inline uint16_t ipip_tunnel_node_process(struct rte_graph *graph,
															 struct rte_node *node,
															 void **objs,
															 uint16_t cnt)
{
	struct rte_mbuf *mbuf0, **pkts;
	rte_edge_t next_index;
	int i;
	struct dp_flow *df;

	pkts = (struct rte_mbuf **)objs;

	for (i = 0; i < cnt; i++) {
		mbuf0 = pkts[i];
		GRAPHTRACE_PKT(node, mbuf0);
		df = get_dp_flow_ptr(mbuf0);
		if (df->flags.flow_type == DP_FLOW_TYPE_OUTGOING)
			next_index = handle_ipip_tunnel_encap(mbuf0, df);
		else if (df->flags.flow_type == DP_FLOW_TYPE_INCOMING)
			next_index = handle_ipip_tunnel_decap(mbuf0, df);
		else
			next_index = IPIP_TUNNEL_NEXT_DROP;
		GRAPHTRACE_PKT_NEXT(node, mbuf0, next_index);
		rte_node_enqueue_x1(graph, node, next_index, mbuf0);
	}

	return cnt;
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
