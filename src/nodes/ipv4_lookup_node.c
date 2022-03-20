#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>
#include "node_api.h"
#include "nodes/ipv4_lookup_priv.h"
#include "nodes/dhcp_node.h"
#include "dp_mbuf_dyn.h"
#include "dp_util.h"
#include "dp_lpm.h"
#include "dp_flow.h"

#include "dp_rte_flow.h"

struct ipv4_lookup_node_main ipv4_lookup_node;

static int ipv4_lookup_node_init(const struct rte_graph *graph, struct rte_node *node)
{
	struct ipv4_lookup_node_ctx *ctx = (struct ipv4_lookup_node_ctx *)node->ctx;

	ctx->next = IPV4_LOOKUP_NEXT_DROP;

	RTE_SET_USED(graph);

	return 0;
}

static __rte_always_inline int handle_ipv4_lookup(struct rte_mbuf *m)
{
	struct dp_flow *df_ptr;
	struct vm_route route;
	int ret = 0;

	df_ptr = get_dp_flow_ptr(m);

	// TODO: add broadcast routes when machine is added
	if (df_ptr->l4_type == DP_IP_PROTO_UDP && ntohs(df_ptr->dst_port) == DP_BOOTP_SRV_PORT)
		return DP_ROUTE_DHCP;

	ret = lpm_get_ip4_dst_port(m->port, df_ptr->tun_info.dst_vni, df_ptr, &route, rte_eth_dev_socket_id(m->port));
	df_ptr->nxt_hop = ret;

	if (df_ptr->flags.flow_type != DP_FLOW_TYPE_INCOMING)
		df_ptr->tun_info.dst_vni = route.vni;

	ret = DP_ROUTE_FIREWALL;
	if (dp_is_pf_port_id(df_ptr->nxt_hop))
	{
		rte_memcpy(df_ptr->tun_info.ul_dst_addr6, route.nh_ipv6, sizeof(df_ptr->tun_info.ul_dst_addr6));
		if (dp_is_vm_natted(m->port))
		{
			ret = DP_ROUTE_NAT;
			df_ptr->flags.nat = DP_NAT_SNAT;
		}
		df_ptr->flags.flow_type = DP_FLOW_TYPE_OUTGOING;
	}

	if (!df_ptr->flags.flow_type)
		df_ptr->flags.flow_type = DP_FLOW_TYPE_LOCAL;

	if (dp_is_offload_enabled())
		df_ptr->flags.valid = 1;

	return ret;
}

static __rte_always_inline uint16_t ipv4_lookup_node_process(struct rte_graph *graph,
															 struct rte_node *node,
															 void **objs,
															 uint16_t cnt)
{
	struct rte_mbuf *mbuf0, **pkts;
	int route;
	int i;

	pkts = (struct rte_mbuf **)objs;

	for (i = 0; i < cnt; i++)
	{
		mbuf0 = pkts[i];
		route = handle_ipv4_lookup(mbuf0);
		if (route >= 0)
			// this is not going to reach
			rte_node_enqueue_x1(graph, node, IPV4_LOOKUP_NEXT_L2_DECAP,
								mbuf0);
		else if (route == DP_ROUTE_DHCP)
			// the ethernet header cannot be removed is due to dhcp node needs mac info
			// TODO: extract mac info in cls node
			rte_node_enqueue_x1(graph, node, IPV4_LOOKUP_NEXT_DHCP, mbuf0);
		else if (route == DP_ROUTE_FIREWALL)
		{
			rte_node_enqueue_x1(graph, node, IPV4_LOOKUP_NEXT_FIREWALL, mbuf0);
		}
		else if (route == DP_ROUTE_NAT)
			rte_node_enqueue_x1(graph, node, IPV4_LOOKUP_NEXT_NAT, mbuf0);
		else
		{
			printf("packet is dropped during ipv4 lookup \n");
			rte_node_enqueue_x1(graph, node, IPV4_LOOKUP_NEXT_DROP, mbuf0);
		}
	}

	return cnt;
}

int ipv4_lookup_set_next(uint16_t port_id, uint16_t next_index)
{

	ipv4_lookup_node.next_index[port_id] = next_index;
	return 0;
}

static struct rte_node_register ipv4_lookup_node_base = {
	.name = "ipv4_lookup",
	.init = ipv4_lookup_node_init,
	.process = ipv4_lookup_node_process,

	.nb_edges = IPV4_LOOKUP_NEXT_MAX,
	.next_nodes =
		{
			[IPV4_LOOKUP_NEXT_DROP] = "drop",
			[IPV4_LOOKUP_NEXT_DHCP] = "dhcp",
			[IPV4_LOOKUP_NEXT_L2_DECAP] = "l2_decap",
			[IPV4_LOOKUP_NEXT_FIREWALL] = "firewall",
			[IPV4_LOOKUP_NEXT_NAT] = "snat",
		},
};

struct rte_node_register *ipv4_lookup_node_get(void)
{
	return &ipv4_lookup_node_base;
}

RTE_NODE_REGISTER(ipv4_lookup_node_base);
