#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_mbuf.h>
#include "node_api.h"
#include "nodes/geneve_encap_node.h"
#include "dp_mbuf_dyn.h"
#include "dp_lpm.h"
#include "dpdk_layer.h"

struct geneve_encap_node_main geneve_encap_node;

static int geneve_encap_node_init(const struct rte_graph *graph, struct rte_node *node)
{
	struct geneve_encap_node_ctx *ctx = (struct geneve_encap_node_ctx *)node->ctx;

	ctx->next = GENEVE_ENCAP_NEXT_DROP;


	RTE_SET_USED(graph);

	return 0;
}

static __rte_always_inline int handle_geneve_encap(struct rte_mbuf *m)
{
	struct underlay_conf *u_conf = get_underlay_conf();
	struct rte_flow_item_geneve *geneve_hdr;
	struct rte_udp_hdr *udp_hdr;
	struct dp_flow *df;

	geneve_hdr = (struct rte_flow_item_geneve *)rte_pktmbuf_prepend(m, sizeof(struct rte_flow_item_geneve));
	udp_hdr = (struct rte_udp_hdr *)rte_pktmbuf_prepend(m, sizeof(struct rte_udp_hdr));

	if (!udp_hdr || !geneve_hdr)
		return 0;

	udp_hdr->dst_port = htons(u_conf->dst_port);
	/* TODO compute here from df values inner 5 tuple a CRC16 hash instead as src port */
	df = get_dp_flow_ptr(m);
	df->flags.geneve_hdr = 1;
	udp_hdr->src_port = htons(u_conf->src_port);

	memcpy(geneve_hdr->vni, &df->dst_vni, sizeof(geneve_hdr->vni));
	geneve_hdr->ver_opt_len_o_c_rsvd0 = 0;
	geneve_hdr->protocol = htons(df->l3_type);
	
	return 1;
} 

static __rte_always_inline uint16_t geneve_encap_node_process(struct rte_graph *graph,
													 struct rte_node *node,
													 void **objs,
													 uint16_t cnt)
{
	struct rte_mbuf *mbuf0, **pkts;
	int i;

	pkts = (struct rte_mbuf **)objs;


	for (i = 0; i < cnt; i++) {
		mbuf0 = pkts[i];
		if (handle_geneve_encap(mbuf0))
			rte_node_enqueue_x1(graph, node, GENEVE_ENCAP_NEXT_IPV6_ENCAP, mbuf0);
		else
			rte_node_enqueue_x1(graph, node, GENEVE_ENCAP_NEXT_DROP, mbuf0);
	}	

    return cnt;
}

int geneve_encap_set_next(uint16_t port_id, uint16_t next_index)
{
	geneve_encap_node.next_index[port_id] = next_index;
	return 0;
}

static struct rte_node_register geneve_encap_node_base = {
	.name = "geneve_encap",
	.init = geneve_encap_node_init,
	.process = geneve_encap_node_process,

	.nb_edges = GENEVE_ENCAP_NEXT_MAX,
	.next_nodes =
		{
			[GENEVE_ENCAP_NEXT_DROP] = "drop",
			[GENEVE_ENCAP_NEXT_IPV6_ENCAP] = "ipv6_encap",
		},
};

struct rte_node_register *geneve_encap_node_get(void)
{
	return &geneve_encap_node_base;
}

RTE_NODE_REGISTER(geneve_encap_node_base);
