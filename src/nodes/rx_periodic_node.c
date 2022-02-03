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
#include "dp_grpc_impl.h"
#include <unistd.h>

static struct rx_periodic_node_ctx node_ctx;
static struct rx_periodic_node_main rx_periodic_node;

int config_rx_periodic_node(struct rx_periodic_node_config *cfg)
{
	node_ctx.periodic_msg_queue = cfg->periodic_msg_queue;
	node_ctx.grpc_tx = cfg->grpc_tx;
	node_ctx.grpc_rx = cfg->grpc_rx;

	return 0;
}

static int rx_periodic_node_init(const struct rte_graph *graph, struct rte_node *node)
{
	struct rx_periodic_node_ctx *ctx = (struct rx_periodic_node_ctx *)node->ctx;
	
	
	ctx->periodic_msg_queue = node_ctx.periodic_msg_queue;
	ctx->grpc_rx = node_ctx.grpc_rx;
	ctx->grpc_tx = node_ctx.grpc_tx;
	ctx->next = RX_PERIODIC_NEXT_CLS;

	printf("rx_periodic_node: init, queue_id: %u\n",
			ctx->queue_id);

	RTE_SET_USED(graph);

	return 0;
}

static __rte_always_inline void check_aged_flows(uint16_t portid)
{
	dp_process_aged_flows(dp_get_pf0_port_id());
	dp_process_aged_flows(dp_get_pf1_port_id());
	dp_process_aged_flows(portid);
}

static __rte_always_inline uint16_t handle_grpc_queue(struct rte_node *node, struct rx_periodic_node_ctx *ctx)
{
	struct rte_mbuf **pkts, *mbuf0;
	int count, i;

	count = rte_ring_dequeue_burst(node_ctx.grpc_tx, node->objs, RTE_GRAPH_BURST_SIZE, NULL);

	if (count == 0)
		return 0;
	pkts = (struct rte_mbuf **)node->objs;

	for (i = 0; i < count; i++) {
		mbuf0 = pkts[i];
		dp_process_request(mbuf0);
	}
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

	if (node_ctx.grpc_tx)
		handle_grpc_queue(node, ctx);

	count = rte_ring_dequeue_burst(ctx->periodic_msg_queue, node->objs, RTE_GRAPH_BURST_SIZE, NULL);
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

	RTE_SET_USED(objs);
	RTE_SET_USED(cnt);

	n_pkts = process_inline(graph, node, ctx);
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