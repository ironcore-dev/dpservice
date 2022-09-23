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

static __rte_always_inline void rewrite_eth_hdr(struct rte_mbuf *m, uint16_t port_id, uint16_t eth_type)
{
	struct rte_ether_hdr *eth_hdr;

	eth_hdr = (struct rte_ether_hdr *)rte_pktmbuf_prepend(m, sizeof(struct rte_ether_hdr));
	rte_ether_addr_copy(dp_get_neigh_mac(port_id), &eth_hdr->dst_addr);
	eth_hdr->ether_type = htons(eth_type);
	rte_ether_addr_copy(dp_get_mac(port_id), &eth_hdr->src_addr);
}

static __rte_always_inline uint16_t tx_node_process(struct rte_graph *graph,
													struct rte_node *node,
													void **objs,
													uint16_t cnt)
{
	struct tx_node_ctx *ctx = (struct tx_node_ctx *)node->ctx;
	struct rte_mbuf *mbuf0, **pkts;
	uint16_t port, queue;
	uint16_t sent_count, i;

	RTE_SET_USED(objs);
	RTE_SET_USED(cnt);

	/* Get Tx port id */
	port = ctx->port_id;
	queue = ctx->queue_id;
	pkts = (struct rte_mbuf **)objs;

	for (i = 0; i < cnt; i++) {
		mbuf0 = pkts[i];
		df = get_dp_flow_ptr(mbuf0);
		if ((mbuf0->port != port && df->periodic_type != DP_PER_TYPE_DIRECT_TX) ||
			(df->flags.nat >= DP_LB_CHG_UL_DST_IP) || df->flags.flow_type == DP_FLOW_TYPE_OUTGOING ) {
			if (dp_is_pf_port_id(port)) {
				rewrite_eth_hdr(mbuf0, port, RTE_ETHER_TYPE_IPV6);
				if (df->flags.nat == DP_LB_RECIRC)
					rte_node_enqueue_x1(graph, node, TX_NEXT_CLS, mbuf0);
			} else {
				rewrite_eth_hdr(mbuf0, port, df->l3_type);
			}
		}

		if (df && df->flags.valid && df->conntrack)
			dp_handle_traffic_forward_offloading(mbuf0, df);
	}

	sent_count = rte_eth_tx_burst(port, queue, (struct rte_mbuf **)objs,
								cnt);

	/* Redirect unsent pkts to drop node */
	if (sent_count != cnt)
		rte_node_enqueue(graph, node, TX_NEXT_DROP,
						&objs[sent_count], cnt - sent_count);

	return sent_count;
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
			[TX_NEXT_DROP] = "drop",
			[TX_NEXT_CLS] = "cls",
		},
};

struct rte_node_register *tx_node_get(void)
{
	return &tx_node_base;
}

RTE_NODE_REGISTER(tx_node_base);
