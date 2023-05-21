#include "nodes/rx_periodic_node.h"
#include <rte_common.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_mbuf.h>
#include "dp_error.h"
#include "dp_flow.h"
#include "dp_mbuf_dyn.h"
#include "grpc/dp_grpc_impl.h"
#include "monitoring/dp_monitoring.h"
#include "nodes/common_node.h"

#define NEXT_NODES(NEXT) \
	NEXT(RX_PERIODIC_NEXT_CLS, "cls")
DP_NODE_REGISTER_SOURCE(RX_PERIODIC, rx_periodic, NEXT_NODES);

static uint16_t next_tx_index[DP_MAX_PORTS];

int rx_periodic_node_append_vf_tx(uint16_t port_id, const char *tx_node_name)
{
	return dp_node_append_vf_tx(DP_NODE_GET_SELF(rx_periodic), next_tx_index, port_id, tx_node_name);
}

// dereference for speed of access
static struct rte_ring *periodic_msg_queue;
static struct rte_ring *grpc_tx_queue;
static struct rte_ring *monitoring_rx_queue;

static int rx_periodic_node_init(__rte_unused const struct rte_graph *graph, __rte_unused struct rte_node *node)
{
	struct dp_dpdk_layer *dp_layer = get_dpdk_layer();

	periodic_msg_queue = dp_layer->periodic_msg_queue;
	grpc_tx_queue = dp_layer->grpc_tx_queue;
	monitoring_rx_queue = dp_layer->monitoring_rx_queue;

	return DP_OK;
}

static __rte_always_inline void handle_nongraph_queues()
{
	struct rte_mbuf *mbufs[DP_INTERNAL_Q_SIZE];
	uint count, i;

	count = rte_ring_sc_dequeue_burst(monitoring_rx_queue, (void **)mbufs, RTE_DIM(mbufs), NULL);
	for (i = 0; i < count; ++i)
		dp_process_event_msg(mbufs[i]);

	count = rte_ring_sc_dequeue_burst(grpc_tx_queue, (void **)mbufs, RTE_DIM(mbufs), NULL);
	for (i = 0; i < count; ++i)
		dp_process_request(mbufs[i]);
}

static __rte_always_inline rte_edge_t get_next_index(__rte_unused struct rte_node *node, struct rte_mbuf *m)
{
	struct dp_flow *df = dp_get_flow_ptr(m);

	if (df->periodic_type == DP_PER_TYPE_DIRECT_TX)
		return next_tx_index[m->port];

	return RX_PERIODIC_NEXT_CLS;
}

static uint16_t rx_periodic_node_process(struct rte_graph *graph,
										 struct rte_node *node,
										 void **objs,
										 uint16_t nb_objs)
{
	uint n_pkts;

	RTE_SET_USED(nb_objs);  // this is a source node, input data is not present yet

	// TODO(plague, separate PR)
	// these actually do not belong here, because they have nothing to do with the graph
	// we are just using the fact that this gets called periodically
	// I would suggest moving them somewhere else
	// temporarily into graph_main_loop, later in a separate core?
	handle_nongraph_queues();

	// these packets do not come from a port, instead they enter the graph from a periodic message
	// which also implies that this will mostly return 0
	n_pkts = rte_ring_dequeue_burst(periodic_msg_queue,
									objs,
									RTE_GRAPH_BURST_SIZE,
									NULL);
	if (likely(!n_pkts))
		return 0;

	node->idx = n_pkts;
	dp_foreach_graph_packet(graph, node, objs, n_pkts, DP_GRAPH_NO_SPECULATED_NODE, get_next_index);
	return n_pkts;
}
