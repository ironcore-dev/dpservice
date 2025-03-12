// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

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
	const struct dp_port *port;
	uint16_t	queue_id;
};
static_assert(sizeof(struct rx_node_ctx) <= RTE_NODE_CTX_SZ,
			  "Rx node context will not fit into the node");

// also some way to map ports to nodes is needed
static rte_node_t rx_node_ids[DP_MAX_PORTS];

// dpservice starts in "standby mode" (no processing of traffic)
static volatile bool standing_by = true;


void rx_node_start_processing(void)
{
	standing_by = false;
}


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

static int rx_node_init(const struct rte_graph *graph, struct rte_node *node)
{
	struct rx_node_ctx *ctx = (struct rx_node_ctx *)node->ctx;
	uint16_t port_id;
	const struct dp_port *port;

	// Find this node's dedicated port to be used in processing
	for (port_id = 0; port_id < RTE_DIM(rx_node_ids); ++port_id)
		if (rx_node_ids[port_id] == node->id)
			break;

	if (port_id >= RTE_DIM(rx_node_ids)) {
		DPNODE_LOG_ERR(node, "No port_id available for this node");
		return DP_ERROR;
	}

	port = dp_get_port_by_id(port_id);
	if (!port) {
		DPNODE_LOG_ERR(node, "Failed to get dp_port during rx_node initialization");
		return DP_ERROR;
	}

	// save dp_port to this node's context for accessing its id and the status of allocation
	ctx->port = port;
	ctx->queue_id = graph->id;
	DPNODE_LOG_INFO(node, "Initialized", DP_LOG_PORTID(ctx->port->port_id), DP_LOG_QUEUEID(ctx->queue_id));
	return DP_OK;
}

static uint16_t rx_node_process(struct rte_graph *graph,
								struct rte_node *node,
								void **objs,
								uint16_t cnt)
{
	struct rx_node_ctx *ctx = (struct rx_node_ctx *)node->ctx;
	uint16_t n_pkts;

	RTE_SET_USED(cnt);  // this is a source node, input data is not present yet

	if (unlikely(!ctx->port->allocated))
		return 0;

	if (unlikely(standing_by))
		return 0;

	n_pkts = rte_eth_rx_burst(ctx->port->port_id,
							  ctx->queue_id,
							  (struct rte_mbuf **)objs,
							  RTE_GRAPH_BURST_SIZE);
	if (unlikely(!n_pkts))
		return 0;

	node->idx = n_pkts;

	// Rx node only ever leads to CLS node (can move all packets at once)
	// also packet tracing in Rx node needs to also cover the ingress itself
	// thus not using dp_foreach_graph_packet() here
	for (uint16_t i = 0; i < n_pkts; ++i)
		dp_init_pkt_mark((struct rte_mbuf *)objs[i]);

	dp_graphtrace_rx_burst(node, objs, n_pkts);

	dp_graphtrace_next_burst(node, objs, n_pkts, RX_NEXT_CLS);

	rte_node_next_stream_move(graph, node, RX_NEXT_CLS);

	return n_pkts;
}
