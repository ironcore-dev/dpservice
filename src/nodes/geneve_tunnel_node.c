#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_mbuf.h>
#include "node_api.h"
#include "dp_mbuf_dyn.h"
#include "dp_log.h"
#include "dp_lpm.h"
#include "dpdk_layer.h"
#include "nodes/common_node.h"
#include "nodes/geneve_tunnel_node.h"
#include "rte_flow/dp_rte_flow.h"

struct geneve_tunnel_node_main geneve_tunnel_node;

static int geneve_tunnel_node_init(const struct rte_graph *graph, struct rte_node *node)
{
	struct geneve_tunnel_node_ctx *ctx = (struct geneve_tunnel_node_ctx *)node->ctx;

	ctx->next = GENEVE_TUNNEL_NEXT_DROP;

	RTE_SET_USED(graph);

	return 0;
}


static __rte_always_inline rte_edge_t handle_geneve_tunnel_encap(struct rte_node *node,
																 struct rte_mbuf *m,
																 struct dp_flow *df)
{
	struct underlay_conf *u_conf = get_underlay_conf();
	struct rte_flow_item_geneve *geneve_hdr;
	struct rte_udp_hdr *udp_hdr;
	// struct dp_flow *df;

	geneve_hdr = (struct rte_flow_item_geneve *)rte_pktmbuf_prepend(m, sizeof(struct rte_flow_item_geneve));
	udp_hdr = (struct rte_udp_hdr *)rte_pktmbuf_prepend(m, sizeof(struct rte_udp_hdr));

	if (unlikely(!udp_hdr || !geneve_hdr)) {
		DPNODE_LOG_WARNING(node, "No space in mbuf for GeNeVe headers");
		return GENEVE_TUNNEL_NEXT_DROP;
	}

	if (RTE_ETH_IS_IPV4_HDR(m->packet_type))
		m->packet_type = RTE_PTYPE_L4_UDP | RTE_PTYPE_TUNNEL_GENEVE | RTE_PTYPE_INNER_L3_IPV4;
	else
		m->packet_type = RTE_PTYPE_L4_UDP | RTE_PTYPE_TUNNEL_GENEVE | RTE_PTYPE_INNER_L3_IPV6;

	udp_hdr->dst_port = htons(u_conf->dst_port);
    df->tun_info.dst_port=htons(u_conf->dst_port);
	/* TODO compute here from df values inner 5 tuple a CRC16 hash instead as src port */
	// df->flags.geneve_hdr = 1;
	udp_hdr->src_port = htons(u_conf->src_port);
    df->tun_info.src_port=htons(u_conf->src_port);
	
	geneve_hdr->ver_opt_len_o_c_rsvd0 = 0;
	geneve_hdr->protocol = htons(df->l3_type);
	// TODO this does not seem right as we are copying into 3B array from an int
	memcpy(geneve_hdr->vni, &df->tun_info.dst_vni, sizeof(geneve_hdr->vni));
	geneve_hdr->rsvd1 = 0;

	df->tun_info.proto_id=DP_IP_PROTO_UDP;
	
	return GENEVE_TUNNEL_NEXT_IPV6_ENCAP;
} 


static __rte_always_inline rte_edge_t handle_geneve_tunnel_decap(struct rte_mbuf *m, struct dp_flow *df)
{
	rte_edge_t next_index = GENEVE_TUNNEL_NEXT_DROP;
	struct rte_flow_item_geneve *geneve_hdr;
	struct rte_udp_hdr *udp_hdr;

	rte_pktmbuf_adj(m, (uint16_t)sizeof(struct rte_ipv6_hdr));

	udp_hdr=rte_pktmbuf_mtod(m, struct rte_udp_hdr*);
	df->tun_info.src_port=udp_hdr->src_port;
	df->tun_info.dst_port=udp_hdr->dst_port;
	
	rte_pktmbuf_adj(m, (uint16_t)sizeof(struct rte_udp_hdr));

	// this shift is non-standard as the actual values of PTYPE should be opaque
	m->packet_type = (m->packet_type & RTE_PTYPE_INNER_L4_MASK) >> 16;
	
	geneve_hdr = rte_pktmbuf_mtod(m, struct rte_flow_item_geneve*);
	rte_memcpy(&df->tun_info.dst_vni, geneve_hdr->vni, sizeof(geneve_hdr->vni));

	rte_pktmbuf_adj(m, (uint16_t)sizeof(struct rte_flow_item_geneve));
	if (ntohs(geneve_hdr->protocol) == RTE_ETHER_TYPE_IPV6) {
		df->l3_type = RTE_ETHER_TYPE_IPV6;
		next_index = GENEVE_TUNNEL_NEXT_IPV6_LOOKUP;
		m->packet_type |= RTE_PTYPE_L3_IPV6;
	} else {
		df->l3_type = RTE_ETHER_TYPE_IPV4;
		next_index = GENEVE_TUNNEL_NEXT_IPV4_LOOKUP;
		m->packet_type |= RTE_PTYPE_L3_IPV4;
	}

	return next_index;
}

static __rte_always_inline rte_edge_t get_next_index(struct rte_node *node, struct rte_mbuf *m)
{
	struct dp_flow *df = get_dp_flow_ptr(m);

	if (df->flags.flow_type == DP_FLOW_TYPE_OUTGOING)
		return handle_geneve_tunnel_encap(node, m, df);

	if (df->flags.flow_type == DP_FLOW_TYPE_INCOMING)
		return handle_geneve_tunnel_decap(m, df);

	return GENEVE_TUNNEL_NEXT_DROP;
}

static uint16_t geneve_tunnel_node_process(struct rte_graph *graph,
										   struct rte_node *node,
										   void **objs,
										   uint16_t nb_objs)
{
	dp_foreach_graph_packet(graph, node, objs, nb_objs, DP_GRAPH_NO_SPECULATED_NODE, get_next_index);
	return nb_objs;
}



int geneve_tunnel_set_next(uint16_t port_id, uint16_t next_index)
{
	geneve_tunnel_node.next_index[port_id] = next_index;
	return 0;
}

static struct rte_node_register geneve_tunnel_node_base = {
	.name = "geneve_tunnel",
	.init = geneve_tunnel_node_init,
	.process = geneve_tunnel_node_process,

	.nb_edges = GENEVE_TUNNEL_NEXT_MAX,
	.next_nodes =
		{
			[GENEVE_TUNNEL_NEXT_DROP] = "drop",
			[GENEVE_TUNNEL_NEXT_IPV6_ENCAP] = "ipv6_encap",
			[GENEVE_TUNNEL_NEXT_IPV4_LOOKUP] = "conntrack",
			[GENEVE_TUNNEL_NEXT_IPV6_LOOKUP] = "ipv6_lookup",
		},
};

struct rte_node_register *geneve_tunnel_node_get(void)
{
	return &geneve_tunnel_node_base;
}

RTE_NODE_REGISTER(geneve_tunnel_node_base);
