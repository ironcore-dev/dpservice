#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_graph.h>
#include <rte_malloc.h>
#include <rte_graph_worker.h>
#include <rte_mbuf.h>
#include "node_api.h"
#include "nodes/common_node.h"
#include "nodes/tx_node_priv.h"
#include "nodes/ipv6_nd_node.h"
#include "dp_error.h"
#include "dp_flow.h"
#include "dp_lpm.h"
#include "dp_util.h"
#include "dp_nat.h"
#include "dp_mbuf_dyn.h"
#include "dp_log.h"

#include "rte_flow/dp_rte_flow.h"
#include "rte_flow/dp_rte_flow_traffic_forward.h"

#define DP_MAX_PATT_ACT 7

static struct ethdev_tx_node_main ethdev_tx_main;
static struct dp_flow *df;

static int tx_node_init(const struct rte_graph *graph, struct rte_node *node)
{
	struct tx_node_ctx *ctx = (struct tx_node_ctx *)node->ctx;
	uint64_t port_id = DP_MAX_PORTS;
	uint16_t i;

	/* Find our port id */
	for (i = 0; i < DP_MAX_PORTS; i++) {
		if (ethdev_tx_main.nodes[i] == node->id) {
			port_id = ethdev_tx_main.port_ids[i];
			break;
		}
	}

	RTE_VERIFY(port_id < DP_MAX_PORTS);

	/* Update port and queue */
	ctx->port_id = port_id;
	ctx->queue_id = graph->id;

	return 0;
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
	uint i;

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

		// tao: make this offload flag as a compilation variable to avoid this function call
		if (dp_conf_is_offload_enabled() && df->conntrack)
			dp_handle_traffic_forward_offloading(pkt, df);
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

struct ethdev_tx_node_main *tx_node_data_get(void)
{
	return &ethdev_tx_main;
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

struct rte_node_register *tx_node_get(void)
{
	return &tx_node_base;
}

RTE_NODE_REGISTER(tx_node_base);
