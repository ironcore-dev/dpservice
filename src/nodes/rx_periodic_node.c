#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_mbuf.h>
#include "nodes/rx_periodic_node.h"
#include "node_api.h"
#include "nodes/ipv6_nd_node.h"
#include "dp_mbuf_dyn.h"
#include "dp_util.h"
#include "dp_flow.h"
#include "grpc/dp_grpc_impl.h"
#include <unistd.h>
#include "monitoring/dp_monitoring.h"
#include "dp_debug.h"

static struct rx_periodic_node_main rx_periodic_node;
static struct rx_periodic_node_receive_queues rx_periodic_node_recv_queues;

int config_rx_periodic_node(struct rx_periodic_node_config *cfg)
{
	rx_periodic_node_recv_queues.periodic_msg_queue = cfg->periodic_msg_queue;
	rx_periodic_node_recv_queues.grpc_tx = cfg->grpc_tx;
	rx_periodic_node_recv_queues.grpc_rx = cfg->grpc_rx;
	rx_periodic_node_recv_queues.monitoring_rx = cfg->monitoring_rx;
	
	return 0;
}

static int rx_periodic_node_init(const struct rte_graph *graph, struct rte_node *node)
{
	struct rx_periodic_node_ctx *ctx = (struct rx_periodic_node_ctx *)node->ctx;

	ctx->next = RX_PERIODIC_NEXT_CLS;

	RTE_SET_USED(graph);

	return 0;
}


static __rte_always_inline void handle_nongraph_queues()
{
	struct rte_mbuf *mbufs[DP_INTERNAL_Q_SIZE];
	uint count, i;

	count = rte_ring_sc_dequeue_burst(rx_periodic_node_recv_queues.monitoring_rx, (void **)mbufs, RTE_DIM(mbufs), NULL);
	for (i = 0; i < count; ++i)
		dp_process_event_msg(mbufs[i]);

	count = rte_ring_sc_dequeue_burst(rx_periodic_node_recv_queues.grpc_tx, (void **)mbufs, RTE_DIM(mbufs), NULL);
	for (i = 0; i < count; ++i)
		dp_process_request(mbufs[i]);
}

static uint16_t rx_periodic_node_process(struct rte_graph *graph,
										 struct rte_node *node,
										 void **objs,
										 uint16_t cnt)
{
	struct rx_periodic_node_ctx *ctx = (struct rx_periodic_node_ctx *)node->ctx;
	struct rte_mbuf *mbuf0;
	struct dp_flow *df_ptr;
	rte_edge_t next_index;
	uint n_pkts, i;

	RTE_SET_USED(cnt);  // this is a source node, input data is not present yet

	// TODO(plague, separate PR)
	// these actually do not belong here, because they have nothing to do with the graph
	// we are just using the fact that this gets called periodically
	// I would suggest moving them somewhere else
	// temporarily into graph_main_loop, later in a separate core?
	handle_nongraph_queues();

	// these packets do not come from a port, instead they enter the graph from a periodic message
	// which also implies that this will mostly return 0
	n_pkts = rte_ring_dequeue_burst(rx_periodic_node_recv_queues.periodic_msg_queue,
									objs,
									RTE_GRAPH_BURST_SIZE,
									NULL);
	if (likely(!n_pkts))
		return 0;

	node->idx = n_pkts;
	for (i = 0; i < n_pkts; ++i) {
		mbuf0 = ((struct rte_mbuf **)objs)[i];
		GRAPHTRACE_PKT(node, mbuf0);
		df_ptr = alloc_dp_flow_ptr(mbuf0);
		if (unlikely(!df_ptr)) {
			DPS_LOG(WARNING, DPSERVICE, "Cannot allocate dp flow pointer for a packet in %s node\n", node->name);
			next_index = RX_PERIODIC_NEXT_DROP;
		} else if (df_ptr->periodic_type == DP_PER_TYPE_DIRECT_TX) {
			if (dp_is_offload_enabled())
				dp_process_aged_flows(mbuf0->port);
			next_index = rx_periodic_node.next_index[mbuf0->port];
		} else
			next_index = ctx->next;
		GRAPHTRACE_PKT_NEXT(node, mbuf0, next_index);
		rte_node_enqueue_x1(graph, node, next_index, mbuf0);
	}

	return n_pkts;
}

int rx_periodic_set_next(uint16_t port_id, uint16_t next_index)
{
	rx_periodic_node.next_index[port_id] = next_index;
	return 0;
}

static struct rte_node_register rx_periodic_node_base = {
	.name = "rx-periodic",
	.flags = RTE_NODE_SOURCE_F,

	.init = rx_periodic_node_init,
	.process = rx_periodic_node_process,

	.nb_edges = RX_PERIODIC_NEXT_MAX,
	.next_nodes =
		{
			[RX_PERIODIC_NEXT_CLS] = "cls",
			[RX_PERIODIC_NEXT_DROP] = "drop",
		},
};

struct rte_node_register *rx_periodic_node_get(void)
{
	return &rx_periodic_node_base;
}

RTE_NODE_REGISTER(rx_periodic_node_base);
