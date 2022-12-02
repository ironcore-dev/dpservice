#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_graph.h>
#include <rte_malloc.h>
#include <rte_graph_worker.h>
#include <rte_mbuf.h>
#include "node_api.h"
#include "nodes/tx_node_priv.h"
#include "nodes/ipv6_nd_node.h"
#include "dp_flow.h"
#include "dp_lpm.h"
#include "dp_util.h"
#include "dp_nat.h"
#include "dp_mbuf_dyn.h"
#include "dp_debug.h"

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
								uint16_t cnt)
{
	struct tx_node_ctx *ctx = (struct tx_node_ctx *)node->ctx;
	struct rte_mbuf *mbuf0, **pkts;
	uint16_t port, queue;
	uint16_t sent_count, i;

	port = ctx->port_id;
	queue = ctx->queue_id;
	pkts = (struct rte_mbuf **)objs;

	for (i = 0; i < cnt; i++) {
		mbuf0 = pkts[i];
		df = get_dp_flow_ptr(mbuf0);
		// TODO what to do here? drop? is is impossible to happen right now,
		// but that's hidden by the function
		// (and the condition was already present below)
		// NOTE: dropping it would break the burst TX below
		if (!df)
			continue;
		// TODO this condition needs some commenting on what it does
		if ((mbuf0->port != port && df->periodic_type != DP_PER_TYPE_DIRECT_TX) ||
			df->flags.nat >= DP_LB_CHG_UL_DST_IP ||
			df->flags.flow_type == DP_FLOW_TYPE_OUTGOING
		) {
			uint16_t new_eth_type = dp_is_pf_port_id(port) ? RTE_ETHER_TYPE_IPV6 : df->l3_type;
			rewrite_eth_hdr(mbuf0, port, new_eth_type);
		}
		if (df->flags.valid && df->conntrack)
			dp_handle_traffic_forward_offloading(mbuf0, df);
	}

	sent_count = rte_eth_tx_burst(port, queue, pkts, cnt);
	GRAPHTRACE_BURST_TX(node, pkts, sent_count, port);

	if (unlikely(sent_count != cnt)) {
		DPS_LOG(WARNING, DPSERVICE, "Not all packets transmitted successfully (%d/%d) in %s node\n", sent_count, cnt, node->name);
		GRAPHTRACE_BURST_NEXT(node, objs + sent_count, cnt - sent_count, TX_NEXT_DROP);
		rte_node_enqueue(graph, node, TX_NEXT_DROP, objs + sent_count, cnt - sent_count);
	}

	// maybe sent_count makes more sense, but cnt is the real number of processed packets by this node
	return cnt;
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
