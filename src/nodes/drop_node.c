#include <rte_debug.h>
#include <rte_graph.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>
#include "node_api.h"
#include "nodes/common_node.h"
#include "dp_mbuf_dyn.h"
#include "dp_util.h"
#include "rte_flow/dp_rte_flow_util.h"


static __rte_always_inline void reset_drop_counter(struct rte_mbuf *m)
{
	struct dp_flow *df_ptr = get_dp_flow_ptr(m);
	struct flow_value *cntrack = df_ptr->conntrack;

	if (!cntrack || cntrack->flow_state != DP_FLOW_STATE_NEW)
		return;

	cntrack->drop_pkt = 0;

}

static __rte_always_inline void react_to_massive_drop(struct rte_mbuf *m, uint16_t nb_objs)
{
	struct flow_value *cntrack = NULL;
	struct dp_flow *df_ptr;

	df_ptr = get_dp_flow_ptr(m);

	if (df_ptr->conntrack)
		cntrack = df_ptr->conntrack;

	if (!cntrack)
		return;

	cntrack->drop_pkt += 1;

	if (cntrack->drop_pkt >= nb_objs) {
		if (dp_is_hw_protection_enabled()) {
			DPS_LOG(DEBUG, DPSERVICE, "Attempt to free flow table entry due to packet drop \n");
			if (!dp_install_protection_drop(m, df_ptr)) {
				DPS_LOG(WARNING, DPSERVICE, "Failed to install a protection drop flow rule \n");
				return;
			} else {
				df_ptr->conntrack->owner += 1;
				dp_free_flow(cntrack);
			}
		} else {
			dp_free_flow(cntrack);
		}
	}

}

static uint16_t drop_node_process(struct rte_graph *graph,
								  struct rte_node *node,
								  void **objs,
								  uint16_t nb_objs)
{
	struct rte_mbuf **pkts = (struct rte_mbuf **)objs;
	struct rte_mbuf *pkt;
	uint i;

	RTE_SET_USED(node);
	RTE_SET_USED(graph);

	for (i = 0; i < nb_objs; i++) {
		pkt = pkts[i];
		reset_drop_counter(pkt);
	}

	for (i = 0; i < nb_objs; i++) {
		pkt = pkts[i];
		dp_graphtrace(node, pkt);
		react_to_massive_drop(pkt, nb_objs);
	}

	rte_pktmbuf_free_bulk(pkts, nb_objs);

	return nb_objs;
}

static struct rte_node_register drop_node_node = {
	.process = drop_node_process,
	.name = "drop",
};

RTE_NODE_REGISTER(drop_node_node);
