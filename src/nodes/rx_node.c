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
	bool		flush_old_packets;
};
static_assert(sizeof(struct rx_node_ctx) <= RTE_NODE_CTX_SZ,
			  "Rx node context will not fit into the node");

// also some way to map ports to nodes is needed
static rte_node_t rx_node_ids[DP_MAX_PORTS];
static struct rx_node_ctx *rx_node_ctxs[DP_MAX_PORTS];

// dpservice starts in "standby mode" (no processing of traffic)
static volatile bool standing_by = true;
static int rx_timestamp_offset;
static uint64_t flush_timestamp;


static uint64_t get_current_timestamp(void)
{
	const struct dp_ports *ports;
	uint64_t timestamp = 0;
	int ret;

	// is timestamping of packets even supported?
	if (rx_timestamp_offset <= 0)
		return 0;

	// PF0/PF1 are in isolated mode, which prevents rte_eth_read_clock() from working
	// thus find the first VF that is up (timestamp is the same for all ports on the NIC)
	ports = dp_get_ports();
	DP_FOREACH_PORT(ports, port) {
		if (!port->allocated)
			continue;
		ret = rte_eth_read_clock(port->port_id, &timestamp);
		if (DP_SUCCESS(ret))
			break;
	}
	return timestamp;
}

void rx_node_start_processing(void)
{
	// even though processing was stopped, buffers still contain old packets
	// to flush them, need to know which ones are old, need current timestamp
	flush_timestamp = get_current_timestamp();
	if (flush_timestamp > 0) {
		// notify all Rx nodes that they need to flush
		for (size_t i = 0; i < RTE_DIM(rx_node_ctxs); ++i)
			if (rx_node_ctxs[i])
				rx_node_ctxs[i]->flush_old_packets = true;
	}

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

	if (rx_timestamp_offset == 0) {
		if (DP_FAILED(rte_mbuf_dyn_rx_timestamp_register(&rx_timestamp_offset, NULL))) {
			DPS_LOG_ERR("Cannot register Rx timestamp field", DP_LOG_RET(rte_errno));
			return DP_ERROR;
		}
	}

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
	rx_node_ctxs[port_id] = ctx;
	DPNODE_LOG_INFO(node, "Initialized", DP_LOG_PORTID(ctx->port->port_id), DP_LOG_QUEUEID(ctx->queue_id));
	return DP_OK;
}


static uint16_t rx_find_old_packets(void **objs, uint16_t n_pkts, uint64_t timestamp)
{
	rte_mbuf_timestamp_t *pkt_timestamp;
	uint16_t old = 0;

	for (uint16_t i = 0; i < n_pkts; ++i) {
		pkt_timestamp = RTE_MBUF_DYNFIELD(objs[i], rx_timestamp_offset, rte_mbuf_timestamp_t *);
		if (*pkt_timestamp >= timestamp)
			break;
		old++;
	}
	return old;
}

static uint16_t rx_node_process(struct rte_graph *graph,
								struct rte_node *node,
								void **objs,
								uint16_t cnt)
{
	struct rx_node_ctx *ctx = (struct rx_node_ctx *)node->ctx;
	uint16_t n_pkts;
	uint16_t old;

	RTE_SET_USED(cnt);  // this is a source node, input data is not present yet

	if (unlikely(!ctx->port->allocated))
		return 0;

	if (unlikely(standing_by))
		return 0;

	n_pkts = rte_eth_rx_burst(ctx->port->port_id, ctx->queue_id, (struct rte_mbuf **)objs, RTE_GRAPH_BURST_SIZE);
	if (unlikely(!n_pkts))
		return 0;

	if (unlikely(ctx->flush_old_packets)) {
		DPS_LOG_INFO("Flushing old packets", DP_LOG_PORT(ctx->port));
		old = rx_find_old_packets(objs, n_pkts, flush_timestamp);
		if (old > 0) {
			rte_pktmbuf_free_bulk((struct rte_mbuf **)objs, old);
			objs += old;
			n_pkts -= old;
			DPS_LOG_INFO("Flushed old packets", DP_LOG_VALUE(old), DP_LOG_PORT(ctx->port));
			// if all packets were old, continue flushing
			if (old == n_pkts)
				return 0;
		}
		ctx->flush_old_packets = false;
	}

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
