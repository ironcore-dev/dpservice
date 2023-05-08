#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_mbuf.h>
#include "dp_conf.h"
#include "dp_flow.h"
#include "dp_lpm.h"
#include "dp_mbuf_dyn.h"
#include "dp_multi_path.h"
#include "dp_port.h"
#include "dp_vnf.h"
#include "node_api.h"
#include "nodes/common_node.h"
#include "nodes/dhcp_node.h"
#include "rte_flow/dp_rte_flow.h"

#define NEXT_NODES(NEXT) \
	NEXT(IPV4_LOOKUP_NEXT_DHCP, "dhcp") \
	NEXT(IPV4_LOOKUP_NEXT_NAT, "snat")
DP_NODE_REGISTER_NOINIT(IPV4_LOOKUP, ipv4_lookup, NEXT_NODES);

static __rte_always_inline rte_edge_t get_next_index(__rte_unused struct rte_node *node, struct rte_mbuf *m)
{
	struct dp_flow *df_ptr = get_dp_flow_ptr(m);
	struct vm_route route;
	uint32_t route_key = 0;
	uint64_t dst_port_id;
	bool nxt_hop_is_pf;

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
	nxt_hop_is_pf = dp_port_is_pf(df_ptr->nxt_hop);

	if (df_ptr->flags.flow_type == DP_FLOW_TYPE_INCOMING) {
		if (nxt_hop_is_pf)
			return IPV4_LOOKUP_NEXT_DROP;
	} else {
		df_ptr->tun_info.dst_vni = route.vni;
		if (nxt_hop_is_pf) {
			rte_memcpy(df_ptr->tun_info.ul_dst_addr6, route.nh_ipv6, sizeof(df_ptr->tun_info.ul_dst_addr6));
			df_ptr->flags.flow_type = DP_FLOW_TYPE_OUTGOING;
		}
	}

	df_ptr->flags.public_flow = route_key == 0 ? DP_FLOW_SOUTH_NORTH : DP_FLOW_WEST_EAST;

	if (!df_ptr->flags.flow_type)
		df_ptr->flags.flow_type = DP_FLOW_TYPE_LOCAL;

	if (df_ptr->flags.flow_type == DP_FLOW_TYPE_LOCAL || df_ptr->flags.flow_type == DP_FLOW_TYPE_INCOMING) {
		if (!nxt_hop_is_pf && dp_port_get_vf_attach_status(df_ptr->nxt_hop) == DP_VF_PORT_DETACHED)
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
