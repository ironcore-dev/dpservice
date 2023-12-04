// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#include <rte_graph.h>
#include <rte_mbuf.h>
#include "nodes/common_node.h"


static uint16_t drop_node_process(struct rte_graph *graph,
								  struct rte_node *node,
								  void **objs,
								  uint16_t nb_objs)
{
	RTE_SET_USED(graph);

	dp_graphtrace_node_burst(node, objs, nb_objs);

	dp_graphtrace_drop_burst(node, objs, nb_objs);

	rte_pktmbuf_free_bulk((struct rte_mbuf **)objs, nb_objs);
	return nb_objs;
}

static struct rte_node_register drop_node_node = {
	.process = drop_node_process,
	.name = "drop",
};

RTE_NODE_REGISTER(drop_node_node);
