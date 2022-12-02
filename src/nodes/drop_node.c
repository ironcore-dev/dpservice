#include <rte_debug.h>
#include <rte_graph.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>
#include "node_api.h"
#include "dp_mbuf_dyn.h"
#include "dp_util.h"
#include "dp_debug.h"


static __rte_always_inline void prepare_drop(struct rte_mbuf *m)
{
	struct dp_flow *df_ptr = get_dp_flow_ptr(m);
	struct flow_value *cntrack = df_ptr->conntrack;

	if (!cntrack || cntrack->flow_state != DP_FLOW_STATE_NEW)
		return;

	DPS_LOG(DEBUG, DPSERVICE, "Attempt to free flow due to packet drop\n");
	dp_free_flow(cntrack);
}

static uint16_t drop_node_process(struct rte_graph *graph,
								  struct rte_node *node,
								  void **objs,
								  uint16_t nb_objs)
{
	struct rte_mbuf *pkt;
	uint i;

	RTE_SET_USED(node);
	RTE_SET_USED(graph);

	for (i = 0; i < nb_objs; ++i) {
		pkt = (struct rte_mbuf *)objs[i];
		GRAPHTRACE_PKT(node, pkt);
		prepare_drop(pkt);
		rte_pktmbuf_free(pkt);
	}

	return nb_objs;
}

static struct rte_node_register drop_node_node = {
	.process = drop_node_process,
	.name = "drop",
};

RTE_NODE_REGISTER(drop_node_node);
