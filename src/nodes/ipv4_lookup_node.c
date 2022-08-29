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

static __rte_always_inline int handle_ipv4_lookup(struct rte_mbuf *m)
{
	struct dp_flow *df_ptr;
	struct vm_route route;
	int ret = 0;
	uint32_t route_key = 0;
	uint64_t dst_port_id;

	df_ptr = get_dp_flow_ptr(m);
	if (!df_ptr)
		return DP_ROUTE_DROP;

	// TODO: add broadcast routes when machine is added
	if (df_ptr->l4_type == DP_IP_PROTO_UDP && ntohs(df_ptr->dst_port) == DP_BOOTP_SRV_PORT)
		return DP_ROUTE_DHCP;

	ret = lpm_lookup_ip4_route(m->port, df_ptr->tun_info.dst_vni, df_ptr, rte_eth_dev_socket_id(m->port), &route, &route_key, &dst_port_id);
	if (ret < 0)
		return DP_ROUTE_DROP;

	//TODO: it is not exactly correct to use next_hop to directly store next hop port id and convert here. but it is already used in
	// such way in the original implementation. as long as port number is limited to 256, it is ok.
	df_ptr->nxt_hop = (uint8_t)dst_port_id;

	df_ptr->flags.public_flow = route_key == 0 ? DP_FLOW_SOUTH_NORTH : DP_FLOW_WEST_EAST;

	if (df_ptr->flags.flow_type != DP_FLOW_TYPE_INCOMING)
		df_ptr->tun_info.dst_vni = route.vni;

	if (dp_is_pf_port_id(df_ptr->nxt_hop)) {
		rte_memcpy(df_ptr->tun_info.ul_dst_addr6, route.nh_ipv6, sizeof(df_ptr->tun_info.ul_dst_addr6));
		df_ptr->flags.flow_type = DP_FLOW_TYPE_OUTGOING;
	}

	if (!df_ptr->flags.flow_type)
		df_ptr->flags.flow_type = DP_FLOW_TYPE_LOCAL;

	if (dp_is_offload_enabled())
		df_ptr->flags.valid = 1;

	if (df_ptr->flags.flow_type==DP_FLOW_TYPE_LOCAL || df_ptr->flags.flow_type==DP_FLOW_TYPE_INCOMING){
		if (!dp_is_pf_port_id(df_ptr->nxt_hop) && get_vf_port_attach_status(df_ptr->nxt_hop) == DP_VF_PORT_DISATTACH)
			return DP_ROUTE_DROP;
	}

	if (df_ptr->flags.flow_type == DP_FLOW_TYPE_OUTGOING) {
		// rewrite outgoing port if WCMP algorithm decides to do so
		if (dp_is_wcmp_enabled()) {
			egress_pf_port selected_port = calculate_port_by_hash(df_ptr->dp_flow_hash);
			struct dp_dpdk_layer *dp_layer = get_dpdk_layer();
			uint16_t owner_port_id = dp_get_pf0_port_id();
			uint16_t peer_port_id = dp_get_pf1_port_id();

			// basic logic of port redundancy if one of ports are down
			if ((selected_port == PEER_PORT && dp_port_get_link_status(dp_layer, peer_port_id) == RTE_ETH_LINK_UP)
				|| (selected_port == OWNER_PORT && dp_port_get_link_status(dp_layer, owner_port_id) == RTE_ETH_LINK_DOWN)) {

				df_ptr->nxt_hop = peer_port_id;
			}
		}
	}

	return 0;
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

	for (i = 0; i < cnt; i++) {
		mbuf0 = pkts[i];
		route = handle_ipv4_lookup(mbuf0);
		if (route >= 0)
			rte_node_enqueue_x1(graph, node, IPV4_LOOKUP_NEXT_NAT,
								mbuf0);
		else if (route == DP_ROUTE_DHCP)
			// the ethernet header cannot be removed is due to dhcp node needs mac info
			// TODO: extract mac info in cls node
			rte_node_enqueue_x1(graph, node, IPV4_LOOKUP_NEXT_DHCP, mbuf0);
		else
			rte_node_enqueue_x1(graph, node, IPV4_LOOKUP_NEXT_DROP, mbuf0);
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
