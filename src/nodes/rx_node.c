#include "nodes/rx_node.h"
#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_mbuf.h>
#include "dp_error.h"
#include "dp_log.h"
#include "dp_port.h"
#include "dp_mbuf_dyn.h"
#include "nodes/common_node.h"

#define NEXT_NODES(NEXT) \
	NEXT(RX_NEXT_CLS, "cls")
DP_NODE_REGISTER_SOURCE(RX, rx, NEXT_NODES);

// there are multiple Tx nodes, one per port, node context is needed
struct rx_node_ctx {
	uint16_t	port_id;
	uint16_t	queue_id;
	bool		enabled;
};
static_assert(sizeof(struct rx_node_ctx) <= RTE_NODE_CTX_SZ,
			  "Rx node context will not fit into the node");

// need to access nodes' context to enable/disable them
static struct rx_node_ctx *node_contexts[DP_MAX_PORTS];

// also some way to map ports to nodes is needed
static rte_node_t rx_node_ids[DP_MAX_PORTS];

int rx_node_create(uint16_t port_id, uint16_t queue_id)
{
	char name[RTE_NODE_NAMESIZE];
	rte_node_t node_id;

	if (port_id >= RTE_DIM(rx_node_ids)) {
		DPS_LOG_ERR("Port id too high for Rx nodes", DP_LOG_VALUE(port_id), DP_LOG_MAX(RTE_DIM(rx_node_ids)));
		return DP_ERROR;
	}

	snprintf(name, sizeof(name), "%u-%u", port_id, queue_id);
	node_id = rte_node_clone(DP_NODE_GET_SELF(rx)->id, name);
	if (node_id == RTE_NODE_ID_INVALID) {
		DPS_LOG_ERR("Cannot clone Rx node", DP_LOG_RET(rte_errno));
		return DP_ERROR;
	}

	rx_node_ids[port_id] = node_id;
	return DP_OK;
}

int rx_node_set_enabled(uint16_t port_id, bool enabled)
{
	if (port_id >= RTE_DIM(node_contexts)) {
		DPS_LOG_ERR("Port id too high for Rx nodes", DP_LOG_VALUE(port_id), DP_LOG_MAX(RTE_DIM(node_contexts)));
		return DP_ERROR;
	}
	node_contexts[port_id]->enabled = enabled;
	return DP_OK;
}


static int rx_node_init(const struct rte_graph *graph, struct rte_node *node)
{
	struct rx_node_ctx *ctx = (struct rx_node_ctx *)node->ctx;
	uint16_t port_id;

	// Find this node's dedicated port to be used in processing
	for (port_id = 0; port_id < RTE_DIM(rx_node_ids); ++port_id)
		if (rx_node_ids[port_id] == node->id)
			break;

	if (port_id >= RTE_DIM(rx_node_ids)) {
		DPNODE_LOG_ERR(node, "No port_id available for this node");
		return DP_ERROR;
	}

	// save pointer to this node's context for enabling/disabling
	node_contexts[port_id] = ctx;

	ctx->port_id = port_id;
	ctx->queue_id = graph->id;
	ctx->enabled = false;
	DPNODE_LOG_INFO(node, "Initialized", DP_LOG_PORTID(ctx->port_id), DP_LOG_QUEUEID(ctx->queue_id));
	return DP_OK;
}

static __rte_always_inline rte_edge_t get_next_index(__rte_unused struct rte_node *node, struct rte_mbuf *m)
{
	dp_init_pkt_mark(m);
	return RX_NEXT_CLS;
}

static uint16_t rx_node_process(struct rte_graph *graph,
								struct rte_node *node,
								void **objs,
								uint16_t cnt)
{
	struct rx_node_ctx *ctx = (struct rx_node_ctx *)node->ctx;
	uint16_t n_pkts = 0;

	RTE_SET_USED(cnt);  // this is a source node, input data is not present yet

	if (unlikely(!ctx->enabled))
		return 0;

	n_pkts = rte_eth_rx_burst(ctx->port_id,
							  ctx->queue_id,
							  (struct rte_mbuf **)objs,
							  RTE_GRAPH_BURST_SIZE);
	if (unlikely(!n_pkts))
		return 0;

	node->idx = n_pkts;

	dp_foreach_graph_packet(graph, node, objs, n_pkts, RX_NEXT_CLS, get_next_index);

	return n_pkts;
}
