// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#include <rte_graph.h>
#include <rte_mbuf.h>
#include "nodes/common_node.h"

DP_NODE_REGISTER(PF1_PROXY, pf1_proxy, DP_NODE_DEFAULT_NEXT_ONLY);

static uint16_t pf1_port_id;
static uint16_t pf1_tap_port_id;

static int pf1_proxy_node_init(__rte_unused const struct rte_graph *graph, __rte_unused struct rte_node *node)
{
	pf1_port_id = dp_get_pf1()->port_id;
	pf1_tap_port_id = dp_get_pf_proxy_tap_port()->port_id;
	return DP_OK;
}

static __rte_always_inline int pf1_proxy_packet(struct rte_node *node,
												struct rte_mbuf *pkt)
{
	uint16_t port_id;
	uint16_t sent_count;

	if (pkt->port == pf1_tap_port_id) {
		port_id = pf1_port_id;
	} else if (pkt->port == pf1_port_id) {
		port_id = pf1_tap_port_id;
	} else {
		DPNODE_LOG_WARNING(node, "Unexpected packet in PF1 Proxy node", DP_LOG_PORTID(pkt->port));
		return DP_ERROR;
	}

	sent_count = rte_eth_tx_burst(port_id, 0, &pkt, 1);
	if (sent_count != 1) {
		DPNODE_LOG_WARNING(node, "Unable to send packet through PF1 Proxy node", DP_LOG_PORTID(pkt->port));
		return DP_ERROR;
	}

	dp_graphtrace_tx_burst(node, (void **)&pkt, 1, port_id);
	return DP_OK;
}

static uint16_t pf1_proxy_node_process(struct rte_graph *graph,
									   struct rte_node *node,
									   void **objs,
									   uint16_t nb_objs)
{
	dp_graphtrace_node_burst(node, objs, nb_objs);

	// since this node is emitting packets, dp_forward_* wrapper functions cannot be used
	// this code should closely resemble the one inside those functions

	for (uint16_t i = 0; i < nb_objs; ++i) {
		if (DP_FAILED(pf1_proxy_packet(node, objs[i]))) {
			dp_graphtrace_next_burst(node, &objs[i], 1, PF1_PROXY_NEXT_DROP);
			rte_node_enqueue(graph, node, PF1_PROXY_NEXT_DROP, &objs[i], 1);
		}
	}

	return nb_objs;
}
