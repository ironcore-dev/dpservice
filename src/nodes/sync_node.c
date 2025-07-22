// SPDX-FileCopyrightText: 2025 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#include "dp_error.h"
#include "nodes/common_node.h"

DP_NODE_REGISTER_SOURCE(SYNC, sync, DP_NODE_DEFAULT_NEXT_ONLY);


static uint16_t sync_port_id;

static int sync_node_init(__rte_unused const struct rte_graph *graph, __rte_unused struct rte_node *node)
{
	sync_port_id = dp_get_sync_port()->port_id;
	return DP_OK;
}


static __rte_always_inline void process_packet(const struct rte_mbuf *pkt)
{
	DPS_LOG_WARNING("SYNC - ", _DP_LOG_INT("len", pkt->data_len));
	struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
	DPS_LOG_WARNING("     - ", _DP_LOG_INT("ethertype", eth_hdr->ether_type));
}

static uint16_t sync_node_process(struct rte_graph *graph,
								  struct rte_node *node,
								  void **objs,
								  uint16_t nb_objs)
{
	uint16_t n_pkts;

	RTE_SET_USED(graph);
	RTE_SET_USED(nb_objs);  // this is a source node, input data is not present yet

	n_pkts = rte_eth_rx_burst(sync_port_id, 0, (struct rte_mbuf **)objs, RTE_GRAPH_BURST_SIZE);
	if (likely(!n_pkts))
		return 0;

	for (uint16_t i = 0; i < n_pkts; ++i)
		process_packet(((struct rte_mbuf **)objs)[i]);

	rte_pktmbuf_free_bulk((struct rte_mbuf **)objs, n_pkts);

	node->idx = n_pkts;
	return n_pkts;
}
