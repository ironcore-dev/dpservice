#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include "node_api.h"
#include "nodes/ipv6_nd_node.h"
#include "dp_lpm.h"
#include "dp_mbuf_dyn.h"
#include "dp_debug.h"


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

static __rte_always_inline int handle_nd(struct rte_mbuf *m) 
{
	struct rte_ether_hdr *req_eth_hdr;
	struct rte_ipv6_hdr *req_ipv6_hdr;
	struct nd_msg *nd_msg;
	struct ra_msg *req_ra_msg;
	struct icmp6hdr *req_icmp6_hdr;
	uint8_t* rt_ip = dp_get_gw_ip6();

	req_eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
	req_ipv6_hdr = (struct rte_ipv6_hdr*) (req_eth_hdr + 1);
	req_icmp6_hdr = (struct icmp6hdr*) (req_ipv6_hdr +1);
	
	rte_ether_addr_copy(&req_eth_hdr->src_addr, &req_eth_hdr->dst_addr);
	rte_memcpy(req_eth_hdr->src_addr.addr_bytes, dp_get_mac(m->port), sizeof(req_eth_hdr->src_addr.addr_bytes));

	if((memcmp(req_ipv6_hdr->src_addr,dp_unspec_ipv6,sizeof(req_ipv6_hdr->src_addr)) == 0)) {
		rte_memcpy(req_ipv6_hdr->dst_addr, dp_mc_ipv6,sizeof(req_ipv6_hdr->dst_addr));		
	} else { 
		rte_memcpy(req_ipv6_hdr->dst_addr, req_ipv6_hdr->src_addr,sizeof(req_ipv6_hdr->dst_addr));
	}
	rte_memcpy(req_ipv6_hdr->src_addr, rt_ip,sizeof(req_ipv6_hdr->src_addr));

	uint8_t type = req_icmp6_hdr->icmp6_type ;

	if( type != NDISC_NEIGHBOUR_SOLICITATION && type != NDISC_ROUTER_SOLICITATION) {
		return 0;

	}
	if( type == NDISC_NEIGHBOUR_SOLICITATION) {
		nd_msg = (struct nd_msg*) (req_ipv6_hdr + 1);
		if((memcmp(&nd_msg->target, rt_ip, sizeof(nd_msg->target))) != 0) {
			return 0;
		}
		dp_set_neigh_mac(m->port, &req_eth_hdr->dst_addr);
		dp_set_vm_ip6(m->port, req_ipv6_hdr->dst_addr);
		req_icmp6_hdr->icmp6_type = NDISC_NEIGHBOUR_ADVERTISEMENT;
		req_icmp6_hdr->icmp6_solicited	= 1;
		req_icmp6_hdr->icmp6_override	= 1;
		// set target lladdr option and MAC
		nd_msg->opt[0] = ND_OPT_TARGET_LL_ADDR;
		nd_msg->opt[1] = ND_OPT_LEN_OCTET_1;
		rte_memcpy(&nd_msg->opt[2],req_eth_hdr->src_addr.addr_bytes,6);
	} else if (type == NDISC_ROUTER_SOLICITATION) {
		req_ra_msg = (struct ra_msg*) (req_ipv6_hdr + 1);
		req_icmp6_hdr->icmp6_type = NDISC_ROUTER_ADVERTISEMENT;
		req_icmp6_hdr->icmp6_managed	= 1;
		req_icmp6_hdr->icmp6_other	= 1;
		req_icmp6_hdr->icmp6_rt_lifetime = 0xffff;
	
		req_ra_msg->reachable_time = 0;
		req_ra_msg->retrans_timer = 0;
		req_ipv6_hdr->payload_len = htons(sizeof(struct ra_msg));
		req_icmp6_hdr->icmp6_hop_limit = 255;
	}

	//L4 cksum calculation 
	req_icmp6_hdr->icmp6_cksum	= 0;
	req_icmp6_hdr->icmp6_cksum = rte_ipv6_udptcp_cksum(req_ipv6_hdr,req_icmp6_hdr);

	return 1;

} 


static __rte_always_inline uint16_t ipv6_nd_node_process(struct rte_graph *graph,
														 struct rte_node *node,
														 void **objs,
														 uint16_t cnt)
{
	struct rte_mbuf *mbuf0, **pkts;
	rte_edge_t next_index;
	int i;

	pkts = (struct rte_mbuf **)objs;

	for (i = 0; i < cnt; i++) {
		mbuf0 = pkts[i];
		GRAPHTRACE_PKT(node, mbuf0);
		if (!dp_is_ip6_overlay_enabled()) {
			next_index = IPV6_ND_NEXT_DROP;
		} else {
			init_dp_mbuf_priv1(mbuf0);
			if (handle_nd(mbuf0))
				next_index = ipv6_nd_node.next_index[mbuf0->port];
			else
				next_index = IPV6_ND_NEXT_DROP;
		}
		GRAPHTRACE_PKT_NEXT(node, mbuf0, next_index);
		rte_node_enqueue_x1(graph, node, next_index, mbuf0);
	}	

	return cnt;
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
