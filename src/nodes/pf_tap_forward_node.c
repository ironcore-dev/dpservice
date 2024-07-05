// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#include <rte_graph.h>
#include <rte_mbuf.h>
#include "nodes/common_node.h"


static uint16_t pf_tap_forward_node_process(struct rte_graph *graph,
								  struct rte_node *node,
								  void **objs,
								  uint16_t nb_objs)
{
	RTE_SET_USED(graph);
	RTE_SET_USED(node);

	struct rte_mbuf *m;

	// since this node is emitting packets, dp_forward_* wrapper functions cannot be used
	// this code should closely resemble the one inside those functions

	for (uint16_t i = 0; i < nb_objs; ++i) {
		m = (struct rte_mbuf *)objs[i];

		if (m->port == dp_get_pf_proxy_tap_port()->port_id)
			rte_eth_tx_burst(dp_get_pf1()->port_id, 0, (struct rte_mbuf **)&objs[i], 1);

		if (m->port == dp_get_pf1()->port_id)
			rte_eth_tx_burst(dp_get_pf_proxy_tap_port()->port_id, 0, (struct rte_mbuf **)&objs[i], 1);

	}
 
	// rte_pktmbuf_free_bulk((struct rte_mbuf **)objs, nb_objs);
	return nb_objs;
}

static struct rte_node_register pf_tap_forward_node = {
	.process = pf_tap_forward_node_process,
	.name = "pf_tap_forward",
};

RTE_NODE_REGISTER(pf_tap_forward_node);
