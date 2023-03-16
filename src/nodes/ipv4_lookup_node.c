#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>
#include "node_api.h"
#include "nodes/common_node.h"
#include "nodes/ipv4_lookup_priv.h"
#include "nodes/dhcp_node.h"
#include "dp_mbuf_dyn.h"
#include "dp_util.h"
#include "dp_lpm.h"
#include "dp_flow.h"
#include "dp_vnf.h"
#include "dp_multi_path.h"

#include "rte_flow/dp_rte_flow.h"

struct ipv4_lookup_node_main ipv4_lookup_node;

static int ipv4_lookup_node_init(const struct rte_graph *graph, struct rte_node *node)
{
	struct ipv4_lookup_node_ctx *ctx = (struct ipv4_lookup_node_ctx *)node->ctx;

	ctx->next = IPV4_LOOKUP_NEXT_DROP;

	RTE_SET_USED(graph);

	return 0;
}

static __rte_always_inline rte_edge_t get_next_index(__rte_unused struct rte_node *node, struct rte_mbuf *m)
{
	struct dp_flow *df_ptr = get_dp_flow_ptr(m);
	struct vm_route route;
	uint32_t route_key = 0;
	uint64_t dst_port_id;

	// TODO: add broadcast routes when machine is added
	if (df_ptr->l4_type == DP_IP_PROTO_UDP && ntohs(df_ptr->l4_info.trans_port.dst_port) == DP_BOOTP_SRV_PORT)
		// the ethernet header cannot be removed is due to dhcp node needs mac info
		// TODO: extract mac info in cls node
		return IPV4_LOOKUP_NEXT_DHCP;

	if (lpm_lookup_ip4_route(m->port, df_ptr->tun_info.dst_vni, df_ptr,
							rte_eth_dev_socket_id(m->port),
							&route, &route_key, &dst_port_id) < 0)
		return IPV4_LOOKUP_NEXT_DROP;
	df_ptr->nxt_hop = (uint8_t)dst_port_id;

	df_ptr->flags.public_flow = route_key == 0 ? DP_FLOW_SOUTH_NORTH : DP_FLOW_WEST_EAST;

	if (df_ptr->flags.flow_type != DP_FLOW_TYPE_INCOMING)
		df_ptr->tun_info.dst_vni = route.vni;

	if (dp_port_is_pf(df_ptr->nxt_hop)) {
		rte_memcpy(df_ptr->tun_info.ul_dst_addr6, route.nh_ipv6, sizeof(df_ptr->tun_info.ul_dst_addr6));
		df_ptr->flags.flow_type = DP_FLOW_TYPE_OUTGOING;
	}

	if (!df_ptr->flags.flow_type)
		df_ptr->flags.flow_type = DP_FLOW_TYPE_LOCAL;

	if (df_ptr->flags.flow_type == DP_FLOW_TYPE_LOCAL || df_ptr->flags.flow_type == DP_FLOW_TYPE_INCOMING) {
		if (!dp_port_is_pf(df_ptr->nxt_hop) && dp_port_get_vf_attach_status(df_ptr->nxt_hop) == DP_VF_PORT_DETACHED)
			return IPV4_LOOKUP_NEXT_DROP;
	}

	if (df_ptr->flags.flow_type == DP_FLOW_TYPE_OUTGOING)
		df_ptr->nxt_hop = dp_multipath_get_pf(df_ptr->dp_flow_hash);

	return IPV4_LOOKUP_NEXT_NAT;
}

static uint16_t ipv4_lookup_node_process(struct rte_graph *graph,
										 struct rte_node *node,
										 void **objs,
										 uint16_t nb_objs)
{
	dp_foreach_graph_packet(graph, node, objs, nb_objs, IPV4_LOOKUP_NEXT_NAT, get_next_index);
	return nb_objs;
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
	.next_nodes = {

			[IPV4_LOOKUP_NEXT_DROP] = "drop",
			[IPV4_LOOKUP_NEXT_DHCP] = "dhcp",
			[IPV4_LOOKUP_NEXT_NAT] = "snat",
		},
};

struct rte_node_register *ipv4_lookup_node_get(void)
{
	return &ipv4_lookup_node_base;
}

RTE_NODE_REGISTER(ipv4_lookup_node_base);
