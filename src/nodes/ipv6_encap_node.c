#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_mbuf.h>
#include "node_api.h"
#include "nodes/ipv6_encap_node.h"
#include "dp_mbuf_dyn.h"
#include "dp_lpm.h"

struct ipv6_encap_node_main ipv6_encap_node;

static int ipv6_encap_node_init(const struct rte_graph *graph, struct rte_node *node)
{
	struct ipv6_encap_node_ctx *ctx = (struct ipv6_encap_node_ctx *)node->ctx;

	ctx->next = IPV6_ENCAP_NEXT_DROP;


	RTE_SET_USED(graph);

	return 0;
}

static __rte_always_inline int handle_ipv6_encap(struct rte_mbuf *m, struct dp_flow * df)
{
	struct underlay_conf *u_conf = get_underlay_conf();
	struct rte_ipv6_hdr *ipv6_hdr;

    m->outer_l2_len = sizeof(struct rte_ether_hdr);
    m->outer_l3_len = sizeof(struct rte_ipv6_hdr);

	ipv6_hdr = (struct rte_ipv6_hdr *)rte_pktmbuf_prepend(m, sizeof(struct rte_ipv6_hdr));

	if (!ipv6_hdr)
			return 0;

	ipv6_hdr->hop_limits = DP_IP6_HOP_LIMIT;
	ipv6_hdr->payload_len = htons(m->pkt_len - sizeof(struct rte_ipv6_hdr));
	ipv6_hdr->vtc_flow = htonl(DP_IP6_VTC_FLOW);
	rte_memcpy(ipv6_hdr->src_addr, u_conf->src_ip6, sizeof(ipv6_hdr->src_addr));
	rte_memcpy(ipv6_hdr->dst_addr, df->tun_info.ul_dst_addr6, sizeof(ipv6_hdr->dst_addr));
	ipv6_hdr->proto = df->tun_info.proto_id;

	m->ol_flags = RTE_MBUF_F_TX_IPV6;

	return 1;
} 

static __rte_always_inline uint16_t ipv6_encap_node_process(struct rte_graph *graph,
													 struct rte_node *node,
													 void **objs,
													 uint16_t cnt)
{
	struct rte_mbuf *mbuf0, **pkts;
	struct dp_flow *df;
	int i;


	pkts = (struct rte_mbuf **)objs;

	for (i = 0; i < cnt; i++) {
		mbuf0 = pkts[i];
		df = get_dp_flow_ptr(mbuf0);
		if (handle_ipv6_encap(mbuf0, df)){
			rte_node_enqueue_x1(graph, node, ipv6_encap_node.next_index[df->nxt_hop], mbuf0);
		}
		else {
			rte_node_enqueue_x1(graph, node, IPV6_ENCAP_NEXT_DROP, mbuf0);

		}
	}	

	return cnt;
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
		},
};

struct rte_node_register *ipv6_encap_node_get(void)
{
	return &ipv6_encap_node_base;
}

RTE_NODE_REGISTER(ipv6_encap_node_base);
