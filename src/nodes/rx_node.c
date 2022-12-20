#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_mbuf.h>
#include "dp_util.h"
#include "nodes/common_node.h"
#include "nodes/rx_node_priv.h"
#include "node_api.h"
#include "dp_debug.h"

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

	DPS_LOG(INFO, DPSERVICE, "rx_node: init, port_id: %u, queue_id: %u\n", ctx->port_id,
			ctx->queue_id);

	RTE_SET_USED(graph);

	return 0;
}

static uint16_t rx_node_process(struct rte_graph *graph,
								struct rte_node *node,
								void **objs,
								uint16_t cnt)
{
	struct rx_node_ctx *ctx = (struct rx_node_ctx *)node->ctx;
	uint16_t n_pkts;

	RTE_SET_USED(cnt);  // this is a source node, input data is not present yet

	if (unlikely(!ethdev_rx_main.node_ctx[ctx->port_id].enabled))
		return 0;

	n_pkts = rte_eth_rx_burst(ctx->port_id,
							  ctx->queue_id,
							  (struct rte_mbuf **)objs,
							  RTE_GRAPH_BURST_SIZE);
	if (unlikely(!n_pkts))
		return 0;

	// TODO hmm, should layer be better accessible? or hide this inside the func? or just a better macro?
	dp_pdump_dump_if_monitored(&get_dpdk_layer()->pdump, ctx->port_id, (struct rte_mbuf **)objs, n_pkts);

	node->idx = n_pkts;
	dp_forward_graph_packets(graph, node, objs, n_pkts, ctx->next);

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
