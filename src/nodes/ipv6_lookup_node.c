#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>
#include "node_api.h"
#include "nodes/ipv6_lookup_node.h"
#include "nodes/ipv6_nd_node.h"
#include "nodes/dhcp_node.h"
#include "nodes/dhcpv6_node.h"
#include "dp_mbuf_dyn.h"
#include "dp_lpm.h"
#include "dp_util.h"

#include "dp_rte_flow.h"

struct ipv6_lookup_node_main ipv6_lookup_node;


static int ipv6_lookup_node_init(const struct rte_graph *graph, struct rte_node *node)
{
	struct ipv6_lookup_node_ctx *ctx = (struct ipv6_lookup_node_ctx *)node->ctx;

	ctx->next = IPV6_LOOKUP_NEXT_DROP;


	RTE_SET_USED(graph);

	return 0;
}

static __rte_always_inline int handle_ipv6_lookup(struct rte_mbuf *m)
{

	int ret = 0;
	int t_vni =0;
	
	struct rte_ipv6_hdr *ipv6_hdr;
	struct vm_route route;
	struct dp_flow *df_ptr;

	ret = DP_ROUTE_DROP;
  
	
	df_ptr = get_dp_flow_ptr(m);
	if (df_ptr->flags.flow_type==DP_FLOW_TYPE_INCOMING){
		t_vni=df_ptr->tun_info.dst_vni;
		ipv6_hdr = rte_pktmbuf_mtod(m, struct rte_ipv6_hdr*);
	}
	else
		ipv6_hdr = rte_pktmbuf_mtod_offset(m, struct rte_ipv6_hdr *,
										  sizeof(struct rte_ether_hdr));

	// if (df_ptr->flags.flow_type!=DP_FLOW_TYPE_INCOMING){
	if (extract_inner_l3_header(m,ipv6_hdr,0)<0){
		printf("failed to extract dp info from inner l3 header \n");
			return IPV6_LOOKUP_NEXT_DROP;
		}

	if (extract_inner_l4_header(m,ipv6_hdr+1,0)<0){
		printf("failed to extract dp info from inner l4 header \n");
		return IPV6_LOOKUP_NEXT_DROP;
	}

	//TODO: add broadcast routes when machine is added
	if (df_ptr->l4_type==DP_IP_PROTO_UDP && ntohs(df_ptr->dst_port)==DHCPV6_SERVER_PORT){
		return IPV6_LOOKUP_NEXT_DHCPV6;
		}
	// }

	ret = lpm_get_ip6_dst_port(m->port, t_vni, ipv6_hdr, &route, rte_eth_dev_socket_id(m->port));
	
	if (ret >= 0){
		df_ptr->nxt_hop = ret;

		if (df_ptr->flags.flow_type!=DP_FLOW_TYPE_INCOMING){
			df_ptr->tun_info.dst_vni = route.vni;
		}

		if (dp_is_pf_port_id(df_ptr->nxt_hop)) {
			rte_memcpy(df_ptr->tun_info.ul_dst_addr6, route.nh_ipv6, sizeof(df_ptr->tun_info.ul_dst_addr6));
			if (dp_is_vm_natted(m->port)) {
				ret = DP_ROUTE_NAT;
				df_ptr->flags.nat = DP_NAT_SNAT;
			}
			df_ptr->flags.flow_type=DP_FLOW_TYPE_OUTGOING;
		}
		
		if (!df_ptr->flags.flow_type)
			df_ptr->flags.flow_type=DP_FLOW_TYPE_LOCAL;
		
		ret = IPV6_LOOKUP_NEXT_L2_DECAP;
		
		if (dp_is_offload_enabled())
			df_ptr->flags.valid = 1;
	}
	
	

	return ret;
}

static __rte_always_inline uint16_t ipv6_lookup_node_process(struct rte_graph *graph,
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
		route = handle_ipv6_lookup(mbuf0);
		if (route > 0)
			rte_node_enqueue_x1(graph, node, route, mbuf0);
		else
			rte_node_enqueue_x1(graph, node, IPV6_LOOKUP_NEXT_DROP, mbuf0);
	}	

	return cnt;
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
			[IPV6_LOOKUP_NEXT_IPV6_DECAP] = "ipv6_decap",
			[IPV6_LOOKUP_NEXT_DHCPV6] = "dhcpv6",
			[IPV6_LOOKUP_NEXT_L2_DECAP] = "l2_decap",
		},
};

struct rte_node_register *ipv6_lookup_node_get(void)
{
	return &ipv6_lookup_node_base;
}

RTE_NODE_REGISTER(ipv6_lookup_node_base);
