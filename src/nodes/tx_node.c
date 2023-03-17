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
#include "dp_util.h"
#include "node_api.h"
#include "nodes/common_node.h"
#include "rte_flow/dp_rte_flow.h"
#include "rte_flow/dp_rte_flow_traffic_forward.h"

enum {
	TX_NEXT_DROP,
	TX_NEXT_MAX
};

// there are multiple Tx nodes, one per port, node context is needed
struct tx_node_ctx {
	uint16_t port_id;
	uint16_t queue_id;
};
_Static_assert(sizeof(struct tx_node_ctx) <= RTE_NODE_CTX_SZ);

// also some way to map ports to nodes is needed
static rte_node_t tx_node_ids[DP_MAX_PORTS];


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
	uint16_t port = ctx->port_id;
	uint16_t queue = ctx->queue_id;
	uint16_t sent_count;
	uint16_t new_eth_type;
	struct rte_mbuf *pkt;
	struct dp_flow *df;
	uint i;
	uint8_t offload_flag = 0;

	// since this node is emitting packets, dp_forward_* wrapper functions cannot be used
	// this code should colely resemble the one inside those functions

	for (i = 0; i < nb_objs; ++i) {
		pkt = (struct rte_mbuf *)objs[i];
		df = get_dp_flow_ptr(pkt);
		// Rewrite ethernet header for all packets except:
		//  - packets created by rewriting a source packet (pkt->port == port)
		//  - packets created by dp_service to directly send to VFs (DP_PER_TYPE_DIRECT_TX)
		// Always rewrite regardless the above for:
		//  - packets coming from loadbalancer node (DP_LB_*)
		//  - packets already encapsulated for outgoing traffic (DP_FLOW_TYPE_OUTGOING)
		if ((pkt->port != port && df->periodic_type != DP_PER_TYPE_DIRECT_TX)
			|| df->flags.nat >= DP_LB_CHG_UL_DST_IP
			|| df->flags.flow_type == DP_FLOW_TYPE_OUTGOING
		) {
			new_eth_type = dp_port_is_pf(port) ? RTE_ETHER_TYPE_IPV6 : df->l3_type;
			if (unlikely(DP_FAILED(rewrite_eth_hdr(pkt, port, new_eth_type))))
				DPNODE_LOG_WARNING(node, "No space in mbuf for ethernet header");
			// since this is done in burst, just send out a bad packet..
		}

		if (df->conntrack) {
			if (df->conntrack->dir == DP_FLOW_DIR_ORG)
				offload_flag = df->conntrack->offload_flags.orig;
			else
				offload_flag = df->conntrack->offload_flags.reply;

			if (offload_flag == DP_FLOW_OFFLOAD_INSTALL || df->flags.offload_ipv6)
				dp_handle_traffic_forward_offloading(pkt, df);
		}
	}

	sent_count = rte_eth_tx_burst(port, queue, (struct rte_mbuf **)objs, nb_objs);
	dp_graphtrace_burst_tx(node, objs, sent_count, port);

	if (unlikely(sent_count != nb_objs)) {
		DPNODE_LOG_WARNING(node, "Not all packets transmitted successfully (%d/%d)", sent_count, nb_objs);
		dp_graphtrace_burst_next(node, objs + sent_count, nb_objs - sent_count, TX_NEXT_DROP);
		rte_node_enqueue(graph, node, TX_NEXT_DROP, objs + sent_count, nb_objs - sent_count);
	}

	// maybe sent_count makes more sense, but cnt is the real number of processed packets by this node
	return nb_objs;
}

static struct rte_node_register tx_node_base = {
	.name = "tx",
	.init = tx_node_init,
	.process = tx_node_process,
	.nb_edges = TX_NEXT_MAX,
	.next_nodes = {
		[TX_NEXT_DROP] = "drop"
	},
};
RTE_NODE_REGISTER(tx_node_base);

int tx_node_create(uint16_t port_id)
{
	char name[RTE_NODE_NAMESIZE];
	rte_node_t node_id;

	if (port_id >= RTE_DIM(tx_node_ids)) {
		DPS_LOG_ERR("Port id %u too high for Tx nodes, max %lu", port_id, RTE_DIM(tx_node_ids));
		return DP_ERROR;
	}

	snprintf(name, sizeof(name), "%u", port_id);
	node_id = rte_node_clone(tx_node_base.id, name);
	if (node_id == RTE_NODE_ID_INVALID) {
		DPS_LOG_ERR("Cannot clone Tx node %s", dp_strerror(rte_errno));
		return DP_ERROR;
	}

	tx_node_ids[port_id] = node_id;
	return DP_OK;
}
