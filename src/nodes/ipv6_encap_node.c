#include "nodes/ipv6_encap_node.h"
#include <rte_common.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_mbuf.h>
#include "dp_error.h"
#include "dp_log.h"
#include "dp_lpm.h"
#include "dp_mbuf_dyn.h"
#include "dp_nat.h"
#include "node_api.h"
#include "nodes/common_node.h"

enum {
	IPV6_ENCAP_NEXT_DROP,
	IPV6_ENCAP_NEXT_CLS,
	IPV6_ENCAP_NEXT_MAX
};

static uint16_t next_tx_index[DP_MAX_PORTS];

static __rte_always_inline rte_edge_t get_next_index(__rte_unused struct rte_node *node, struct rte_mbuf *m)
{
	struct dp_flow *df = get_dp_flow_ptr(m);
	struct underlay_conf *u_conf = get_underlay_conf();
	struct rte_ipv6_hdr *ipv6_hdr;
	uint32_t tunnel_type = dp_conf_get_overlay_type() == DP_CONF_OVERLAY_TYPE_GENEVE
		? RTE_PTYPE_TUNNEL_GENEVE
		: RTE_PTYPE_TUNNEL_IP;
	// TODO(plague): optimization PR - u_conf and tunnel_type can be prepared in init()

	m->outer_l2_len = sizeof(struct rte_ether_hdr);
	m->outer_l3_len = sizeof(struct rte_ipv6_hdr);
	m->l2_len = 0; /* We dont have inner l2, when we encapsulate */

	ipv6_hdr = (struct rte_ipv6_hdr *)rte_pktmbuf_prepend(m, sizeof(struct rte_ipv6_hdr));
	if (unlikely(!ipv6_hdr)) {
		DPNODE_LOG_WARNING(node, "No space in mbuf for IPv6 header");
		return IPV6_ENCAP_NEXT_DROP;
	}

	ipv6_hdr->hop_limits = DP_IP6_HOP_LIMIT;
	ipv6_hdr->payload_len = htons(m->pkt_len - sizeof(struct rte_ipv6_hdr));
	ipv6_hdr->vtc_flow = htonl(DP_IP6_VTC_FLOW);
	rte_memcpy(ipv6_hdr->src_addr, u_conf->src_ip6, sizeof(ipv6_hdr->src_addr));
	rte_memcpy(ipv6_hdr->dst_addr, df->tun_info.ul_dst_addr6, sizeof(ipv6_hdr->dst_addr));
	ipv6_hdr->proto = df->tun_info.proto_id;

	if (ipv6_hdr->proto == IPPROTO_IPIP)
		m->packet_type = RTE_PTYPE_L3_IPV6 | tunnel_type | RTE_PTYPE_INNER_L3_IPV4;
	else
		m->packet_type = RTE_PTYPE_L3_IPV6 | tunnel_type | RTE_PTYPE_INNER_L3_IPV6;

	m->ol_flags |= RTE_MBUF_F_TX_OUTER_IPV6;
	m->ol_flags |= RTE_MBUF_F_TX_TUNNEL_IP;

	if (df->flags.nat == DP_LB_RECIRC) {
		if (unlikely(DP_FAILED(rewrite_eth_hdr(m, df->nxt_hop, RTE_ETHER_TYPE_IPV6)))) {
			DPNODE_LOG_WARNING(node, "No space in mbuf for ethernet header");
			return IPV6_ENCAP_NEXT_DROP;
		}
		return IPV6_ENCAP_NEXT_CLS;
	}

	return next_tx_index[df->nxt_hop];
} 

static uint16_t ipv6_encap_node_process(struct rte_graph *graph,
										struct rte_node *node,
										void **objs,
										uint16_t nb_objs)
{
	dp_foreach_graph_packet(graph, node, objs, nb_objs, DP_GRAPH_NO_SPECULATED_NODE, get_next_index);
	return nb_objs;
}

static struct rte_node_register ipv6_encap_node_base = {
	.name = "ipv6_encap",
	.init = NULL,
	.process = ipv6_encap_node_process,
	.nb_edges = IPV6_ENCAP_NEXT_MAX,
	.next_nodes = {
		[IPV6_ENCAP_NEXT_DROP] = "drop",
		[IPV6_ENCAP_NEXT_CLS] = "cls",
	},
};
RTE_NODE_REGISTER(ipv6_encap_node_base);

int ipv6_encap_node_append_pf_tx(uint16_t port_id, const char *tx_node_name)
{
	return dp_node_append_pf_tx(&ipv6_encap_node_base, next_tx_index, port_id, tx_node_name);
}
