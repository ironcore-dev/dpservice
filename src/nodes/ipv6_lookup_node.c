#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>
#include "node_api.h"
#include "nodes/ipv6_lookup_node.h"
#include "nodes/dhcp_node.h"
#include "nodes/dhcpv6_node.h"
#include "dp_mbuf_dyn.h"
#include "dp_lpm.h"

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
	int ret = 0;

	if ((m->packet_type & (RTE_PTYPE_L4_UDP))) {
		udp_hdr = rte_pktmbuf_mtod_offset(m, struct rte_udp_hdr *,
									sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv6_hdr));
		u_conf = get_underlay_conf();
		if (ntohs(udp_hdr->dst_port) == u_conf->src_port){
			rte_pktmbuf_adj(m, (uint16_t)sizeof(struct rte_ether_hdr));
			ret = IPV6_LOOKUP_NEXT_IPV6_DECAP;
		}
		else if (ntohs(udp_hdr->dst_port) == DHCPV6_SERVER_PORT) {
			ret = IPV6_LOOKUP_NEXT_DHCPV6;
		}
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
		if (route)
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
		},
};

struct rte_node_register *ipv6_lookup_node_get(void)
{
	return &ipv6_lookup_node_base;
}

RTE_NODE_REGISTER(ipv6_lookup_node_base);
