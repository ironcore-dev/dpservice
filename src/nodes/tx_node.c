#include "nodes/tx_node.h"
#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_mbuf.h>
#include "dp_error.h"
#include "dp_log.h"
#include "dp_mbuf_dyn.h"
#include "dp_nat.h"
#include "dp_port.h"
#include "nodes/common_node.h"
#include "rte_flow/dp_rte_flow.h"
#include "rte_flow/dp_rte_flow_traffic_forward.h"

DP_NODE_REGISTER(TX, tx, DP_NODE_DEFAULT_NEXT_ONLY);

// there are multiple Tx nodes, one per port, node context is needed
struct tx_node_ctx {
	uint16_t port_id;
	uint16_t queue_id;
};
static_assert(sizeof(struct tx_node_ctx) <= RTE_NODE_CTX_SZ,
			  "Tx node context will not fit into the node");

// also some way to map ports to nodes is needed
static rte_node_t tx_node_ids[DP_MAX_PORTS];

int tx_node_create(uint16_t port_id)
{
	char name[RTE_NODE_NAMESIZE];
	rte_node_t node_id;

	if (port_id >= RTE_DIM(tx_node_ids)) {
		DPS_LOG_ERR("Port id too high for Tx nodes", DP_LOG_VALUE(port_id), DP_LOG_MAX(RTE_DIM(tx_node_ids)));
		return DP_ERROR;
	}

	snprintf(name, sizeof(name), "%u", port_id);
	node_id = rte_node_clone(DP_NODE_GET_SELF(tx)->id, name);
	if (node_id == RTE_NODE_ID_INVALID) {
		DPS_LOG_ERR("Cannot clone Tx node", DP_LOG_RET(rte_errno));
		return DP_ERROR;
	}

	tx_node_ids[port_id] = node_id;
	return DP_OK;
}


static int tx_node_init(const struct rte_graph *graph, struct rte_node *node)
{
	struct tx_node_ctx *ctx = (struct tx_node_ctx *)node->ctx;
	uint16_t port_id;

	// Find this node's dedicated port to be used in processing
	for (port_id = 0; port_id < RTE_DIM(tx_node_ids); ++port_id)
		if (tx_node_ids[port_id] == node->id)
			break;

	if (port_id >= RTE_DIM(tx_node_ids)) {
		DPNODE_LOG_ERR(node, "No port_id available for this node");
		return DP_ERROR;
	}

	ctx->port_id = port_id;
	ctx->queue_id = graph->id;
	return DP_OK;
}

static uint16_t tx_node_process(struct rte_graph *graph,
								struct rte_node *node,
								void **objs,
								uint16_t nb_objs)
{
	struct tx_node_ctx *ctx = (struct tx_node_ctx *)node->ctx;
	uint16_t port_id = ctx->port_id;
	uint16_t queue = ctx->queue_id;
	uint16_t sent_count;
	struct rte_mbuf *m;
	struct dp_flow *df;

	// since this node is emitting packets, dp_forward_* wrapper functions cannot be used
	// this code should closely resemble the one inside those functions

	for (uint16_t i = 0; i < nb_objs; ++i) {
		m = (struct rte_mbuf *)objs[i];
		df = dp_get_flow_ptr(m);
		if (df->conntrack) {
			// mark the flow as default if it is not marked as any other status
			if (!DP_IS_FLOW_STATUS_FLAG_NF(df->conntrack->flow_status))
				df->conntrack->flow_status |= DP_FLOW_STATUS_FLAG_DEFAULT;
			// offload this flow from now on
			if (df->flags.offload_decision == DP_FLOW_OFFLOAD_INSTALL || df->flags.offload_ipv6)
				if (DP_FAILED(dp_offload_handler(m, df)))
					DPNODE_LOG_WARNING(node, "Offloading handler failed");
		}
	}

	sent_count = rte_eth_tx_burst(port_id, queue, (struct rte_mbuf **)objs, nb_objs);
	dp_graphtrace_tx_burst(node, objs, sent_count, port_id);

	if (unlikely(sent_count != nb_objs)) {
		DPNODE_LOG_WARNING(node, "Not all packets transmitted successfully", DP_LOG_VALUE(sent_count), DP_LOG_MAX(nb_objs));
		dp_graphtrace_next_burst(node, objs + sent_count, nb_objs - sent_count, TX_NEXT_DROP);
		rte_node_enqueue(graph, node, TX_NEXT_DROP, objs + sent_count, nb_objs - sent_count);
	}

	// maybe sent_count makes more sense, but cnt is the real number of processed packets by this node
	return nb_objs;
}
