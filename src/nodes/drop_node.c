#include <rte_debug.h>
#include <rte_graph.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>
#include "node_api.h"
#include "dp_mbuf_dyn.h"

static uint16_t drop_node_process(struct rte_graph *graph,
								  struct rte_node *node,
								  void **objs,
								  uint16_t nb_objs)
{
	struct rte_mbuf *mbuf0, **pkts;
	struct dp_flow *df;
	int i;

	RTE_SET_USED(node);
	RTE_SET_USED(graph);

	pkts = (struct rte_mbuf **)objs;


	for (i = 0; i < nb_objs; i++) {
		mbuf0 = pkts[i];
		df = get_dp_flow_ptr(mbuf0);
		rte_free(df);
	}

	rte_pktmbuf_free_bulk((struct rte_mbuf **)objs, nb_objs);

	return nb_objs;
}

static struct rte_node_register drop_node_node = {
	.process = drop_node_process,
	.name = "drop",
};

RTE_NODE_REGISTER(drop_node_node);
