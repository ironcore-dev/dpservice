#include <rte_debug.h>
#include <rte_graph.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>
#include "node_api.h"
#include "nodes/common_node.h"
#include "dp_mbuf_dyn.h"
#include "dp_util.h"


static uint16_t drop_node_process(struct rte_graph *graph,
								  struct rte_node *node,
								  void **objs,
								  uint16_t nb_objs)
{
	struct rte_mbuf **pkts = (struct rte_mbuf **)objs;

	RTE_SET_USED(node);
	RTE_SET_USED(graph);

	rte_pktmbuf_free_bulk(pkts, nb_objs);
	return nb_objs;
}

static struct rte_node_register drop_node_node = {
	.process = drop_node_process,
	.name = "drop",
};

RTE_NODE_REGISTER(drop_node_node);
