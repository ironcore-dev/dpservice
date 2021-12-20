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
	struct underlay_conf *u_conf;
	struct rte_udp_hdr *udp_hdr;
	int ret = 0, t_vni = 0;
	struct rte_ipv6_hdr *ipv6_hdr;
	struct rte_tcp_hdr *tcp_hdr;
	struct icmp6hdr *icmp_hdr;
	struct vm_route route;
	struct dp_flow df;
	struct dp_flow *df_ptr;

	ipv6_hdr = rte_pktmbuf_mtod_offset(m, struct rte_ipv6_hdr *,
								sizeof(struct rte_ether_hdr));
	memset(&df, 0, sizeof(struct dp_flow));
	df.l3_type = RTE_ETHER_TYPE_IPV6;
	df.l4_type = ipv6_hdr->proto;

	if(ipv6_hdr->proto == DP_IP_PROTO_UDP ) {
		udp_hdr = rte_pktmbuf_mtod_offset(m, struct rte_udp_hdr *,
									sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv6_hdr));
		u_conf = get_underlay_conf();
		if (ntohs(udp_hdr->dst_port) == u_conf->src_port){
			rte_pktmbuf_adj(m, (uint16_t)sizeof(struct rte_ether_hdr));
			return IPV6_LOOKUP_NEXT_IPV6_DECAP;
		}
		else if (ntohs(udp_hdr->dst_port) == DHCPV6_SERVER_PORT) {
			return IPV6_LOOKUP_NEXT_DHCPV6;
		} else {
			df.dst_port = udp_hdr->dst_port;
			df.src_port = udp_hdr->src_port;
			
		}
	} else if (ipv6_hdr->proto == DP_IP_PROTO_TCP ) {
		tcp_hdr = rte_pktmbuf_mtod_offset(m, struct rte_tcp_hdr *,
									sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv6_hdr));
		df.dst_port = tcp_hdr->dst_port;
		df.src_port = tcp_hdr->src_port;
	} else if (ipv6_hdr->proto == DP_IP_PROTO_ICMPV6 ) {
		icmp_hdr = rte_pktmbuf_mtod_offset(m, struct icmp6hdr *,
									sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv6_hdr));
		df.icmp_type = icmp_hdr->icmp6_type;

	}
	rte_memcpy(df.dst.dst_addr6, ipv6_hdr->dst_addr,sizeof(df.dst.dst_addr6));
	rte_memcpy(df.src.src_addr6, ipv6_hdr->src_addr,sizeof(df.src.src_addr6));
	df.l4_type = ipv6_hdr->proto;

	ret = lpm_get_ip6_dst_port(m->port, t_vni, ipv6_hdr, &route, rte_eth_dev_socket_id(m->port));
	df.nxt_hop = ret;
	df_ptr = alloc_dp_flow_ptr(m);
	if (!df_ptr)
		return DP_ROUTE_DROP;
	rte_memcpy(df_ptr, &df, sizeof(struct dp_flow));
	ret = IPV6_LOOKUP_NEXT_L2_DECAP;
	if (dp_is_offload_enabled())
			df_ptr->valid = 1;

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
			rte_node_enqueue_x1(graph, node, route, *objs);
		else
			rte_node_enqueue_x1(graph, node, IPV6_LOOKUP_NEXT_DROP, *objs);
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
