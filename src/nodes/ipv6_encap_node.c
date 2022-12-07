#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_mbuf.h>
#include "node_api.h"
#include "nodes/common_node.h"
#include "nodes/ipv6_encap_node.h"
#include "dp_mbuf_dyn.h"
#include "dp_lpm.h"
#include "dp_nat.h"
#include "dp_debug.h"

struct ipv6_encap_node_main ipv6_encap_node;

static int ipv6_encap_node_init(const struct rte_graph *graph, struct rte_node *node)
{
	struct ipv6_encap_node_ctx *ctx = (struct ipv6_encap_node_ctx *)node->ctx;

	ctx->next = IPV6_ENCAP_NEXT_DROP;

	RTE_SET_USED(graph);

	return 0;
}

static __rte_always_inline rte_edge_t get_next_index(struct rte_mbuf *m)
{
	struct dp_flow *df = get_dp_flow_ptr(m);
	struct underlay_conf *u_conf = get_underlay_conf();
	struct rte_ipv6_hdr *ipv6_hdr;

	m->outer_l2_len = sizeof(struct rte_ether_hdr);
	m->outer_l3_len = sizeof(struct rte_ipv6_hdr);
	m->l2_len = 0; /* We dont have inner l2, when we encapsulate */

	ipv6_hdr = (struct rte_ipv6_hdr *)rte_pktmbuf_prepend(m, sizeof(struct rte_ipv6_hdr));
	if (unlikely(!ipv6_hdr))
		return IPV6_ENCAP_NEXT_DROP;

	ipv6_hdr->hop_limits = DP_IP6_HOP_LIMIT;
	ipv6_hdr->payload_len = htons(m->pkt_len - sizeof(struct rte_ipv6_hdr));
	ipv6_hdr->vtc_flow = htonl(DP_IP6_VTC_FLOW);
	rte_memcpy(ipv6_hdr->src_addr, u_conf->src_ip6, sizeof(ipv6_hdr->src_addr));
	rte_memcpy(ipv6_hdr->dst_addr, df->tun_info.ul_dst_addr6, sizeof(ipv6_hdr->dst_addr));
	ipv6_hdr->proto = df->tun_info.proto_id;

	m->ol_flags |= RTE_MBUF_F_TX_OUTER_IPV6;
	m->ol_flags |= RTE_MBUF_F_TX_TUNNEL_IP;

	if (df->flags.nat == DP_LB_RECIRC) {
		rewrite_eth_hdr(m, df->nxt_hop, RTE_ETHER_TYPE_IPV6);
		return IPV6_ENCAP_NEXT_CLS;
	}

	return ipv6_encap_node.next_index[df->nxt_hop];
} 

static uint16_t ipv6_encap_node_process(struct rte_graph *graph,
										struct rte_node *node,
										void **objs,
										uint16_t nb_objs)
{
	dp_foreach_graph_packet(graph, node, objs, nb_objs, get_next_index);
	return nb_objs;
}

int ipv6_encap_set_next(uint16_t port_id, uint16_t next_index)
{
	ipv6_encap_node.next_index[port_id] = next_index;
	return 0;
}

static struct rte_node_register ipv6_encap_node_base = {
	.name = "ipv6_encap",
	.init = ipv6_encap_node_init,
	.process = ipv6_encap_node_process,

	.nb_edges = IPV6_ENCAP_NEXT_MAX,
	.next_nodes =
		{
			[IPV6_ENCAP_NEXT_DROP] = "drop",
			[IPV6_ENCAP_NEXT_CLS] = "cls",
		},
};

struct rte_node_register *ipv6_encap_node_get(void)
{
	return &ipv6_encap_node_base;
}

RTE_NODE_REGISTER(ipv6_encap_node_base);
