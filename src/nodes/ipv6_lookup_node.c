#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_mbuf.h>
#include "dp_lpm.h"
#include "dp_mbuf_dyn.h"
#include "dp_util.h"
#include "nodes/common_node.h"
#include "protocols/dp_dhcpv6.h"
#include "rte_flow/dp_rte_flow.h"

#define NEXT_NODES(NEXT) \
	NEXT(IPV6_LOOKUP_NEXT_DHCPV6, "dhcpv6") \
	NEXT(IPV6_LOOKUP_NEXT_L2_DECAP, "l2_decap")
DP_NODE_REGISTER_NOINIT(IPV6_LOOKUP, ipv6_lookup, NEXT_NODES);

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
		df_ptr->flags.offload_ipv6 = 1;

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
