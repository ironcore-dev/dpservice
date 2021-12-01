#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_mbuf.h>
#include "node_api.h"
#include "nodes/geneve_decap_node.h"
#include "dp_mbuf_dyn.h"
#include "dp_lpm.h"
#include "dpdk_layer.h"

struct geneve_decap_node_main geneve_decap_node;

static int geneve_decap_node_init(const struct rte_graph *graph, struct rte_node *node)
{
	struct geneve_decap_node_ctx *ctx = (struct geneve_decap_node_ctx *)node->ctx;

	ctx->next = GENEVE_DECAP_NEXT_DROP;


	RTE_SET_USED(graph);

	return 0;
}

static __rte_always_inline int handle_geneve_decap(struct rte_mbuf *m)
{
	/* Pop the udp header */
	rte_pktmbuf_adj(m, (uint16_t)sizeof(struct rte_udp_hdr));
	return 1;
} 

static __rte_always_inline uint16_t geneve_decap_node_process(struct rte_graph *graph,
													 struct rte_node *node,
													 void **objs,
													 uint16_t cnt)
{
	struct rte_mbuf *mbuf0, **pkts;
	int i;

	pkts = (struct rte_mbuf **)objs;


	for (i = 0; i < cnt; i++) {
		mbuf0 = pkts[i];
		if (handle_geneve_decap(mbuf0))
			rte_node_enqueue_x1(graph, node, GENEVE_DECAP_NEXT_IPV4_LOOKUP, *objs);
		else
			rte_node_enqueue_x1(graph, node, GENEVE_DECAP_NEXT_DROP, *objs);
	}	

    return cnt;
}

int geneve_decap_set_next(uint16_t port_id, uint16_t next_index)
{
	geneve_decap_node.next_index[port_id] = next_index;
	return 0;
}

static struct rte_node_register geneve_decap_node_base = {
	.name = "geneve_decap",
	.init = geneve_decap_node_init,
	.process = geneve_decap_node_process,

	.nb_edges = GENEVE_DECAP_NEXT_MAX,
	.next_nodes =
		{
			[GENEVE_DECAP_NEXT_DROP] = "drop",
			[GENEVE_DECAP_NEXT_IPV4_LOOKUP] = "ipv4_lookup",
		},
};

struct rte_node_register *geneve_decap_node_get(void)
{
	return &geneve_decap_node_base;
}

RTE_NODE_REGISTER(geneve_decap_node_base);
