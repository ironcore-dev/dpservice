#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_mbuf.h>
#include "nodes/rx_node_priv.h"
#include "node_api.h"

static struct ethdev_rx_node_main ethdev_rx_main;

int config_rx_node(struct rx_node_config *cfg)
{
	int idx = cfg->port_id;

	RTE_VERIFY(idx < DP_MAX_PORTS);

	ethdev_rx_main.node_ctx[idx].port_id  = cfg->port_id;
	ethdev_rx_main.node_ctx[idx].queue_id  = cfg->queue_id;
	ethdev_rx_main.node_ctx[idx].node_id  = cfg->node_id;
	ethdev_rx_main.node_ctx[idx].enabled = false;

	return 0;
}

void enable_rx_node(uint16_t portid)
{
	RTE_VERIFY(portid < DP_MAX_PORTS);

	ethdev_rx_main.node_ctx[portid].enabled = true;
}

void disable_rx_node(uint16_t portid)
{
	RTE_VERIFY(portid < DP_MAX_PORTS);

	ethdev_rx_main.node_ctx[portid].enabled = false;
}

static int rx_node_init(const struct rte_graph *graph, struct rte_node *node)
{
	struct rx_node_ctx *ctx = (struct rx_node_ctx *)node->ctx;
	int i, port_id = 0;

	for (i = 0; i < DP_MAX_PORTS; i++) {
		if (ethdev_rx_main.node_ctx[i].node_id == node->id) {
			port_id = ethdev_rx_main.node_ctx[i].port_id;
			break;
		}
	}
	ctx->port_id = ethdev_rx_main.node_ctx[port_id].port_id;
	ctx->queue_id = ethdev_rx_main.node_ctx[port_id].queue_id;
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
	uint16_t count = 0, next_index;
	uint16_t port, queue;

	port = ctx->port_id;
	queue = ctx->queue_id;
	next_index = ctx->next;

	/* Get pkts from port */
	if (ethdev_rx_main.node_ctx[ctx->port_id].enabled)
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
		},
};

struct rte_node_register *rx_node_get(void)
{
	return &rx_node_base;
}

RTE_NODE_REGISTER(rx_node_base);
