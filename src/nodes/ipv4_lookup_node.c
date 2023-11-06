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
#include "nodes/common_node.h"
#include "nodes/dhcp_node.h"
#include "rte_flow/dp_rte_flow.h"

#define NEXT_NODES(NEXT) \
	NEXT(IPV4_LOOKUP_NEXT_DHCP, "dhcp") \
	NEXT(IPV4_LOOKUP_NEXT_NAT, "snat")
DP_NODE_REGISTER_NOINIT(IPV4_LOOKUP, ipv4_lookup, NEXT_NODES);

static __rte_always_inline rte_edge_t get_next_index(__rte_unused struct rte_node *node, struct rte_mbuf *m)
{
	struct dp_flow *df = dp_get_flow_ptr(m);
	struct vm_route route;
	uint32_t route_key = 0;
	uint64_t dst_port_id;
	bool nxt_hop_is_pf;

	// TODO: add broadcast routes when machine is added
	if (df->l4_type == DP_IP_PROTO_UDP && df->l4_info.trans_port.dst_port == htons(DP_BOOTP_SRV_PORT))
		return IPV4_LOOKUP_NEXT_DHCP;

	if (DP_FAILED(dp_lookup_ip4_route(m->port, df->tun_info.dst_vni, df,
									  rte_eth_dev_socket_id(m->port),
									  &route, &route_key, &dst_port_id)))
		return IPV4_LOOKUP_NEXT_DROP;

	df->nxt_hop = (uint8_t)dst_port_id;
	nxt_hop_is_pf = dp_port_is_pf(df->nxt_hop);

	if (df->flags.flow_type == DP_FLOW_TYPE_INCOMING) {
		if (nxt_hop_is_pf)
			return IPV4_LOOKUP_NEXT_DROP;
	} else {
		df->tun_info.dst_vni = route.vni;
		if (nxt_hop_is_pf) {
			rte_memcpy(df->tun_info.ul_dst_addr6, route.nh_ipv6, sizeof(df->tun_info.ul_dst_addr6));
			df->flags.flow_type = DP_FLOW_TYPE_OUTGOING;
		}
	}

	df->flags.public_flow = route_key == 0 ? DP_FLOW_SOUTH_NORTH : DP_FLOW_WEST_EAST;

	if (!df->flags.flow_type)
		df->flags.flow_type = DP_FLOW_TYPE_LOCAL;

	if (df->flags.flow_type == DP_FLOW_TYPE_LOCAL || df->flags.flow_type == DP_FLOW_TYPE_INCOMING) {
		if (!nxt_hop_is_pf && !dp_is_vf_attached(df->nxt_hop))
			return IPV4_LOOKUP_NEXT_DROP;
	}

	if (df->flags.flow_type == DP_FLOW_TYPE_OUTGOING) {
		df->nxt_hop = dp_multipath_get_pf_id(df->dp_flow_hash);
		nxt_hop_is_pf = true;
	}

	// next hop is known, fill in Ether header
	// (PF egress goes through a tunnel that destroys Ether header)
	if (!nxt_hop_is_pf)
		dp_fill_ether_hdr(rte_pktmbuf_mtod(m, struct rte_ether_hdr *), df->nxt_hop, RTE_ETHER_TYPE_IPV4);

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
