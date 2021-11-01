#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_mbuf.h>
#include "node_api.h"

enum
{
	RX_NEXT_CLS,
	RX_NEXT_DROP,
	RX_NEXT_MAX
};

struct rx_node_ctx
{
	uint16_t port_id;
	uint16_t queue_id;
	uint16_t next;
};

static struct rx_node_ctx g_rx_node_ctx;

int config_rx_node(struct rx_node_config *cfg)
{
	g_rx_node_ctx.port_id = cfg->port_id;
	g_rx_node_ctx.queue_id = cfg->queue_id;

	return 0;
}


static int rx_node_init(const struct rte_graph *graph, struct rte_node *node)
{
	struct rx_node_ctx *ctx = (struct rx_node_ctx *)node->ctx;

	ctx->port_id = g_rx_node_ctx.port_id;
	ctx->queue_id = g_rx_node_ctx.queue_id;
	ctx->next = RX_NEXT_CLS;

	printf("rx_node: init, port_id: %u, queue_id: %u\n", ctx->port_id,
			ctx->queue_id);

	RTE_SET_USED(graph);

	return 0;
}

static __rte_always_inline uint16_t process_inline(struct rte_graph *graph,
												   struct rte_node *node,
												   struct rx_node_ctx *ctx)
{
	uint16_t count, next_index;
	uint16_t port, queue;

	port = ctx->port_id;
	queue = ctx->queue_id;
	next_index = ctx->next;

	/* Get pkts from port */
	count = rte_eth_rx_burst(port, queue, (struct rte_mbuf **)node->objs,
								RTE_GRAPH_BURST_SIZE);

	if (!count)
		return 0;

	node->idx = count;
	/* Enqueue to next node */
	rte_node_next_stream_move(graph, node, next_index);

	return count;
}

static __rte_always_inline uint16_t rx_node_process(struct rte_graph *graph,
													struct rte_node *node,
													void **objs,
													uint16_t cnt)
{
	struct rx_node_ctx *ctx = (struct rx_node_ctx *)node->ctx;
	uint16_t n_pkts = 0;

	RTE_SET_USED(objs);
	RTE_SET_USED(cnt);

	n_pkts = process_inline(graph, node, ctx);
	return n_pkts;
}

static struct rte_node_register rx_node_base = {
	.name = "rx",
	.flags = RTE_NODE_SOURCE_F,

	.init = rx_node_init,
	.process = rx_node_process,

	.nb_edges = RX_NEXT_MAX,
	.next_nodes =
		{
			[RX_NEXT_CLS] = "cls",
			[RX_NEXT_DROP] = "drop",
		},
};

struct rte_node_register *rx_node_get(void)
{
	return &rx_node_base;
}

RTE_NODE_REGISTER(rx_node_base);
