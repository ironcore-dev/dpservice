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
	struct rte_flow_item_geneve *geneve_hdr;
	struct rte_ipv4_hdr *ipv4_hdr;
	struct rte_udp_hdr *udp_hdr;
	struct rte_tcp_hdr *tcp_hdr;
	struct rte_icmp_hdr *icmp_hdr;
	struct dp_flow df;
	struct dp_flow *df_ptr;
	struct vm_route route;
	struct flow_key key;
	int ret = 0, t_vni = 0;

	memset(&key, 0, sizeof(struct flow_key));
	memset(&df, 0, sizeof(struct dp_flow));
	df.l3_type = RTE_ETHER_TYPE_IPV4;

	if (dp_is_pf_port_id(m->port)) {
		geneve_hdr = rte_pktmbuf_mtod(m, struct rte_flow_item_geneve*);
		rte_pktmbuf_adj(m, (uint16_t)sizeof(struct rte_flow_item_geneve));
		ipv4_hdr = rte_pktmbuf_mtod(m, struct rte_ipv4_hdr*);
		rte_memcpy(&t_vni, geneve_hdr->vni, sizeof(geneve_hdr->vni));
		df.geneve_hdr = 1;
	} else {
		ipv4_hdr = rte_pktmbuf_mtod_offset(m, struct rte_ipv4_hdr *,
										  sizeof(struct rte_ether_hdr));
	}
	if (ipv4_hdr->next_proto_id == DP_IP_PROTO_TCP) {
		tcp_hdr = rte_pktmbuf_mtod_offset(m, struct rte_tcp_hdr *,
							sizeof(struct rte_ether_hdr)
							+ sizeof(struct rte_ipv4_hdr));
		df.dst_port = tcp_hdr->dst_port;
		df.src_port = tcp_hdr->src_port;
	} else if (ipv4_hdr->next_proto_id == DP_IP_PROTO_UDP) {
		udp_hdr = rte_pktmbuf_mtod_offset(m, struct rte_udp_hdr *,
										sizeof(struct rte_ether_hdr)
										+ sizeof(struct rte_ipv4_hdr));
		if ((ntohs(udp_hdr->dst_port) == DP_BOOTP_SRV_PORT) && !df.geneve_hdr)
				return DP_ROUTE_DHCP;
		df.dst_port = udp_hdr->dst_port;
		df.src_port = udp_hdr->src_port;
	} else if (ipv4_hdr->next_proto_id == DP_IP_PROTO_ICMP) {
		icmp_hdr = (struct rte_icmp_hdr *)rte_pktmbuf_mtod_offset(m,
										struct rte_udp_hdr *,
										sizeof(struct rte_ether_hdr)
										+ sizeof(struct rte_ipv4_hdr));
		df.icmp_type = icmp_hdr->icmp_type;
	}
	df.dst.dst_addr = ipv4_hdr->dst_addr;
	df.src.src_addr = ipv4_hdr->src_addr;
	df.l4_type = ipv4_hdr->next_proto_id;

	ret = lpm_get_ip4_dst_port(m->port, t_vni, ipv4_hdr, &route, rte_eth_dev_socket_id(m->port));
	if (ret >= 0) {
		df.nxt_hop = ret;
		df_ptr = alloc_dp_flow_ptr(m);
		if (!df_ptr)
			return DP_ROUTE_DROP;
		rte_memcpy(df_ptr, &df, sizeof(struct dp_flow));
		if (!t_vni) /* VM -> Outer world */
			df_ptr->dst_vni = route.vni;
		else /* Outer world -> VM */
			df_ptr->dst_vni = t_vni;

		dp_build_flow_key(&key, df_ptr);
		if (!dp_flow_exists(m->port, &key))
			dp_add_flow(m->port, &key);

		if (dp_is_pf_port_id(df_ptr->nxt_hop))
			rte_memcpy(df_ptr->ul_dst_addr6, route.nh_ipv6, sizeof(df_ptr->ul_dst_addr6));
		else
			ret = DP_ROUTE_FIREWALL;

		if (dp_is_offload_enabled())
			df_ptr->valid = 1;
	}
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

	for (i = 0; i < cnt; i++) {
		mbuf0 = pkts[i];
		route = handle_ipv4_lookup(mbuf0);
		if (route >= 0) 
			rte_node_enqueue_x1(graph, node, IPV4_LOOKUP_NEXT_L2_DECAP, 
								mbuf0);
		else if (route == DP_ROUTE_DHCP)
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
	.next_nodes =
		{
			[IPV4_LOOKUP_NEXT_DROP] = "drop",
			[IPV4_LOOKUP_NEXT_DHCP] = "dhcp",
			[IPV4_LOOKUP_NEXT_L2_DECAP] = "l2_decap",
		},
};

struct rte_node_register *ipv4_lookup_node_get(void)
{
	return &ipv4_lookup_node_base;
}

RTE_NODE_REGISTER(ipv4_lookup_node_base);
