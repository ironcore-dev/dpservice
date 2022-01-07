#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_mbuf.h>
#include "nodes/rx_periodic_node.h"
#include "node_api.h"
#include "nodes/ipv6_nd_node.h"
#include <unistd.h>

static struct rx_periodic_node_ctx node_ctx;

int config_rx_periodic_node(struct rx_periodic_node_config *cfg)
{
    node_ctx.periodic_msg_queue = cfg->periodic_msg_queue;
	return 0;
}

static int rx_periodic_node_init(const struct rte_graph *graph, struct rte_node *node)
{
	struct rx_periodic_node_ctx *ctx = (struct rx_periodic_node_ctx *)node->ctx;
	
	
	ctx->periodic_msg_queue = node_ctx.periodic_msg_queue;
	ctx->next = RX_PERIODIC_NEXT_CLS;

	printf("rx_periodic_node: init, queue_id: %u\n",
			ctx->queue_id);

	RTE_SET_USED(graph);

	return 0;
}

/* static __rte_always_inline uint16_t handle_msg_queue(struct rte_node *node, struct rx_periodic_node_ctx *ctx)
{
	struct rte_mbuf **pkts, *mbuf0;
	int count, i;
    uint8_t comp = 0;
    struct rte_ether_hdr *req_eth_hdr;
	struct rte_ipv6_hdr *req_ipv6_hdr;
	struct icmp6hdr *req_icmp6_hdr;

	count = rte_ring_dequeue_burst(ctx->periodic_msg_queue, node->objs, RTE_GRAPH_BURST_SIZE, NULL);

	if (count == 0)
		return 0;

	pkts = (struct rte_mbuf **)node->objs;

	for (i = 0; i < count; i++) {
		mbuf0 = pkts[i];
		
        init_dp_mbuf_priv1(mbuf0);
        

	req_eth_hdr = rte_pktmbuf_mtod(mbuf0, struct rte_ether_hdr *);
	req_ipv6_hdr = (struct rte_ipv6_hdr*) (req_eth_hdr + 1);
	req_icmp6_hdr = (struct icmp6hdr*) (req_ipv6_hdr + 1);
	uint8_t type = req_icmp6_hdr->icmp6_type ;

	}
	return 0;
} */

static __rte_always_inline uint16_t process_inline(struct rte_graph *graph,
												   struct rte_node *node,
												   struct rx_periodic_node_ctx *ctx)
{
	uint16_t count, next_index;

	next_index = ctx->next;

	count = rte_ring_dequeue_burst(ctx->periodic_msg_queue, node->objs, RTE_GRAPH_BURST_SIZE, NULL);
	if (!count)
		return 0;
	node->idx = count;
	
	printf("sats:in rx periodic q: %d\n",count);
	
	/* Enqueue to next node */
	rte_node_next_stream_move(graph, node, next_index);

	return count;
}

static __rte_always_inline uint16_t rx_periodic_node_process(struct rte_graph *graph,
													struct rte_node *node,
													void **objs,
													uint16_t cnt)
{
	struct rx_periodic_node_ctx *ctx = (struct rx_periodic_node_ctx *)node->ctx;
	uint16_t n_pkts = 0;

	RTE_SET_USED(objs);
	RTE_SET_USED(cnt);

	n_pkts = process_inline(graph, node, ctx);
	return n_pkts;
}



static struct rte_node_register rx_periodic_node_base = {
	.name = "rx-periodic",
	.flags = RTE_NODE_SOURCE_F,

	.init = rx_periodic_node_init,
	.process = rx_periodic_node_process,

	.nb_edges = RX_PERIODIC_NEXT_MAX,
	.next_nodes =
		{
			[RX_PERIODIC_NEXT_CLS] = "cls",
		},
};

struct rte_node_register *rx_periodic_node_get(void)
{
	return &rx_periodic_node_base;
}

RTE_NODE_REGISTER(rx_periodic_node_base);