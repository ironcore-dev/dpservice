#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>
#include "node_api.h"
#include "nodes/common_node.h"
#include "nodes/ipv6_lookup_node.h"
#include "nodes/ipv6_nd_node.h"
#include "nodes/dhcp_node.h"
#include "nodes/dhcpv6_node.h"
#include "dp_mbuf_dyn.h"
#include "dp_lpm.h"
#include "dp_util.h"
#include "rte_flow/dp_rte_flow.h"

struct ipv6_lookup_node_main ipv6_lookup_node;

static int ipv6_lookup_node_init(const struct rte_graph *graph, struct rte_node *node)
{
	struct ipv6_lookup_node_ctx *ctx = (struct ipv6_lookup_node_ctx *)node->ctx;

	ctx->next = IPV6_LOOKUP_NEXT_DROP;

	RTE_SET_USED(graph);

	return 0;
}

static __rte_always_inline rte_edge_t get_next_index(__rte_unused struct rte_node *node, struct rte_mbuf *m)
{
	struct dp_flow *df_ptr = get_dp_flow_ptr(m);
	struct rte_ipv6_hdr *ipv6_hdr;
	struct vm_route route;
	int t_vni;
	int ret;

	if (df_ptr->flags.flow_type == DP_FLOW_TYPE_INCOMING) {
		t_vni = df_ptr->tun_info.dst_vni;
		ipv6_hdr = rte_pktmbuf_mtod(m, struct rte_ipv6_hdr *);
	} else {
		t_vni = 0;
		ipv6_hdr = rte_pktmbuf_mtod_offset(m, struct rte_ipv6_hdr *,
										   sizeof(struct rte_ether_hdr));
	}

	if (extract_inner_l3_header(m, ipv6_hdr, 0) < 0)
		return IPV6_LOOKUP_NEXT_DROP;

	if (extract_inner_l4_header(m, ipv6_hdr + 1, 0) < 0)
		return IPV6_LOOKUP_NEXT_DROP;

	// TODO: add broadcast routes when machine is added
	if (df_ptr->l4_type == DP_IP_PROTO_UDP && ntohs(df_ptr->l4_info.trans_port.dst_port) == DHCPV6_SERVER_PORT)
		return IPV6_LOOKUP_NEXT_DHCPV6;

	ret = lpm_get_ip6_dst_port(m->port, t_vni, ipv6_hdr, &route, rte_eth_dev_socket_id(m->port));
	if (ret < 0)
		return IPV6_LOOKUP_NEXT_DROP;

	df_ptr->nxt_hop = ret;

	if (df_ptr->flags.flow_type != DP_FLOW_TYPE_INCOMING)
		df_ptr->tun_info.dst_vni = route.vni;

	if (dp_port_is_pf(df_ptr->nxt_hop)) {
		rte_memcpy(df_ptr->tun_info.ul_dst_addr6, route.nh_ipv6, sizeof(df_ptr->tun_info.ul_dst_addr6));
		df_ptr->flags.flow_type = DP_FLOW_TYPE_OUTGOING;
	}

	if (!df_ptr->flags.flow_type)
		df_ptr->flags.flow_type = DP_FLOW_TYPE_LOCAL;

	if (dp_conf_is_offload_enabled())
		df_ptr->flags.valid = 1;

	return IPV6_LOOKUP_NEXT_L2_DECAP;
}

static uint16_t ipv6_lookup_node_process(struct rte_graph *graph,
										 struct rte_node *node,
										 void **objs,
										 uint16_t nb_objs)
{
	dp_foreach_graph_packet(graph, node, objs, nb_objs, IPV6_LOOKUP_NEXT_L2_DECAP, get_next_index);
	return nb_objs;
}

int ipv6_lookup_set_next(uint16_t port_id, uint16_t next_index)
{
	ipv6_lookup_node.next_index[port_id] = next_index;
	return 0;
}

static struct rte_node_register ipv6_lookup_node_base = {
	.name = "ipv6_lookup",
	.init = ipv6_lookup_node_init,
	.process = ipv6_lookup_node_process,

	.nb_edges = IPV6_LOOKUP_NEXT_MAX,
	.next_nodes =
		{
			[IPV6_LOOKUP_NEXT_DROP] = "drop",
			[IPV6_LOOKUP_NEXT_DHCPV6] = "dhcpv6",
			[IPV6_LOOKUP_NEXT_L2_DECAP] = "l2_decap",
		},
};

struct rte_node_register *ipv6_lookup_node_get(void)
{
	return &ipv6_lookup_node_base;
}

RTE_NODE_REGISTER(ipv6_lookup_node_base);
