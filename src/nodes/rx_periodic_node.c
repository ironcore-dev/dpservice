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

static __rte_always_inline void check_aged_flows(uint16_t portid)
{
	if (dp_is_offload_enabled())
		dp_process_aged_flows(portid);
}

static __rte_always_inline uint16_t handle_monitoring_queue(struct rte_node *node, struct rx_periodic_node_ctx *ctx){
	struct rte_mbuf *mbufs[32];
	struct rte_mbuf *mbuf0;
	int count = 0, i;

	count = rte_ring_sc_dequeue_burst(rx_periodic_node_recv_queues.monitoring_rx, (void **)mbufs, 32, NULL);

	if (count == 0) {
		return 0;
	}

	for (i = 0; i < count; i++) {
		mbuf0 = mbufs[i];
		dp_process_event_msg(mbuf0);
	}

	RTE_SET_USED(ctx);

	return 0;
}

static __rte_always_inline uint16_t handle_grpc_queue(struct rte_node *node, struct rx_periodic_node_ctx *ctx)
{
	struct rte_mbuf **pkts, *mbuf0;
	int count, i;

	// RTE_GRAPH_BURST_SIZE seems not a good value to set, since the capacity of ring is 32.
	count = rte_ring_sc_dequeue_burst(rx_periodic_node_recv_queues.grpc_tx, node->objs, RTE_GRAPH_BURST_SIZE, NULL);

	if (count == 0)
		return 0;
	pkts = (struct rte_mbuf **)node->objs;

	for (i = 0; i < count; i++) {
		mbuf0 = pkts[i];
		dp_process_request(mbuf0);
	}

	RTE_SET_USED(ctx);	

	return 0;
}


static __rte_always_inline uint16_t process_inline(struct rte_graph *graph,
												   struct rte_node *node,
												   struct rx_periodic_node_ctx *ctx)
{
	struct rte_mbuf **pkts, *mbuf0;
	uint16_t count, next_index;
	struct dp_flow *df_ptr;
 	int i;

	next_index = ctx->next;

	// which condition grpc_tx is null? 
	if (rx_periodic_node_recv_queues.grpc_tx)
		handle_grpc_queue(node, ctx);

	if (rx_periodic_node_recv_queues.monitoring_rx)
		handle_monitoring_queue(node,ctx);

	count = rte_ring_dequeue_burst(rx_periodic_node_recv_queues.periodic_msg_queue, node->objs, RTE_GRAPH_BURST_SIZE, NULL);
	if (!count)
		return 0;
	
	pkts = (struct rte_mbuf **)node->objs;
 	for (i = 0; i < count; i++) {
 		node->idx = 1;
 		mbuf0 = pkts[i];
 		df_ptr = alloc_dp_flow_ptr(mbuf0);
 		if (!df_ptr)
 			continue;
 		if (df_ptr->periodic_type == DP_PER_TYPE_DIRECT_TX) {
			check_aged_flows(mbuf0->port);
 			next_index = rx_periodic_node.next_index[mbuf0->port];
		}
 		rte_node_enqueue_x1(graph, node, next_index, mbuf0);
 	}

	return count;
}

static __rte_always_inline uint16_t rx_periodic_node_process(struct rte_graph *graph,
													struct rte_node *node,
													void **objs,
													uint16_t cnt)
{
	struct rx_periodic_node_ctx *ctx = (struct rx_periodic_node_ctx *)node->ctx;
	uint16_t n_pkts = 0;
	uint16_t next_index = ctx->next;

	RTE_SET_USED(objs);
	RTE_SET_USED(cnt);

	n_pkts = process_inline(graph, node, ctx);

	ctx->next = next_index;

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
		},
};

struct rte_node_register *rx_periodic_node_get(void)
{
	return &rx_periodic_node_base;
}

RTE_NODE_REGISTER(rx_periodic_node_base);