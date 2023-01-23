#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include "node_api.h"
#include "nodes/common_node.h"
#include "nodes/ipv6_nd_node.h"
#include "dp_lpm.h"
#include "dp_mbuf_dyn.h"


struct ipv6_nd_node_main ipv6_nd_node;
static uint8_t dp_unspec_ipv6[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
static uint8_t dp_mc_ipv6[16] = {0xff,0x02,0,0,0,0,0,0,0,0,0,0,0,0,0,0x01};
 
static int ipv6_nd_node_init(const struct rte_graph *graph, struct rte_node *node)
{
	struct ipv6_nd_node_ctx *ctx = (struct ipv6_nd_node_ctx *)node->ctx;

	ctx->next = IPV6_ND_NEXT_DROP;

	RTE_SET_USED(graph);

	return 0;
}

static __rte_always_inline rte_edge_t get_next_index(__rte_unused struct rte_node *node, struct rte_mbuf *m)
{
	struct rte_ether_hdr *req_eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
	struct rte_ipv6_hdr *req_ipv6_hdr = (struct rte_ipv6_hdr *)(req_eth_hdr + 1);
	struct icmp6hdr *req_icmp6_hdr = (struct icmp6hdr *)(req_ipv6_hdr + 1);
	uint8_t icmp_type = req_icmp6_hdr->icmp6_type;
	const uint8_t *rt_ip = dp_get_gw_ip6();
	struct nd_msg *nd_msg;
	struct ra_msg *req_ra_msg;

	init_dp_mbuf_priv1(m);
	
	rte_ether_addr_copy(&req_eth_hdr->src_addr, &req_eth_hdr->dst_addr);
	rte_memcpy(req_eth_hdr->src_addr.addr_bytes, dp_get_mac(m->port), sizeof(req_eth_hdr->src_addr.addr_bytes));

	if (!memcmp(req_ipv6_hdr->src_addr, dp_unspec_ipv6, sizeof(req_ipv6_hdr->src_addr)))
		rte_memcpy(req_ipv6_hdr->dst_addr, dp_mc_ipv6, sizeof(req_ipv6_hdr->dst_addr));
	else
		rte_memcpy(req_ipv6_hdr->dst_addr, req_ipv6_hdr->src_addr, sizeof(req_ipv6_hdr->dst_addr));

	rte_memcpy(req_ipv6_hdr->src_addr, rt_ip, sizeof(req_ipv6_hdr->src_addr));

	if (icmp_type != NDISC_NEIGHBOUR_SOLICITATION && icmp_type != NDISC_ROUTER_SOLICITATION)
		return IPV6_ND_NEXT_DROP;

	if (icmp_type == NDISC_NEIGHBOUR_SOLICITATION) {
		nd_msg = (struct nd_msg *)(req_ipv6_hdr + 1);
		if (memcmp(&nd_msg->target, rt_ip, sizeof(nd_msg->target)))
			return IPV6_ND_NEXT_DROP;
		dp_set_neigh_mac(m->port, &req_eth_hdr->dst_addr);
		dp_set_vm_ip6(m->port, req_ipv6_hdr->dst_addr);
		req_icmp6_hdr->icmp6_type = NDISC_NEIGHBOUR_ADVERTISEMENT;
		req_icmp6_hdr->icmp6_solicited = 1;
		req_icmp6_hdr->icmp6_override = 1;
		// set target lladdr option and MAC
		nd_msg->opt[0] = ND_OPT_TARGET_LL_ADDR;
		nd_msg->opt[1] = ND_OPT_LEN_OCTET_1;
		rte_memcpy(&nd_msg->opt[2],req_eth_hdr->src_addr.addr_bytes,6);
	} else if (icmp_type == NDISC_ROUTER_SOLICITATION) {
		req_ra_msg = (struct ra_msg *)(req_ipv6_hdr + 1);
		req_icmp6_hdr->icmp6_type = NDISC_ROUTER_ADVERTISEMENT;
		req_icmp6_hdr->icmp6_managed = 1;
		req_icmp6_hdr->icmp6_other = 1;
		req_icmp6_hdr->icmp6_rt_lifetime = 0xffff;
		req_ra_msg->reachable_time = 0;
		req_ra_msg->retrans_timer = 0;
		req_ipv6_hdr->payload_len = htons(sizeof(struct ra_msg));
		req_icmp6_hdr->icmp6_hop_limit = 255;
	}

	req_icmp6_hdr->icmp6_cksum = 0;
	req_icmp6_hdr->icmp6_cksum = rte_ipv6_udptcp_cksum(req_ipv6_hdr,req_icmp6_hdr);

	return ipv6_nd_node.next_index[m->port];
} 


static uint16_t ipv6_nd_node_process(struct rte_graph *graph,
									 struct rte_node *node,
									 void **objs,
									 uint16_t nb_objs)
{
	if (dp_conf_is_ipv6_overlay_enabled())
		dp_foreach_graph_packet(graph, node, objs, nb_objs, get_next_index);
	else
		dp_forward_graph_packets(graph, node, objs, nb_objs, IPV6_ND_NEXT_DROP);

	return nb_objs;
}

int ipv6_nd_set_next(uint16_t port_id, uint16_t next_index)
{
	ipv6_nd_node.next_index[port_id] = next_index;
	return 0;
}

static struct rte_node_register ipv6_nd_node_base = {
	.name = "ipv6_nd",
	.init = ipv6_nd_node_init,
	.process = ipv6_nd_node_process,

	.nb_edges = IPV6_ND_NEXT_MAX,
	.next_nodes =
		{
			[IPV6_ND_NEXT_DROP] = "drop",
		},
};

struct rte_node_register *ipv6_nd_node_get(void)
{
	return &ipv6_nd_node_base;
}

RTE_NODE_REGISTER(ipv6_nd_node_base);
