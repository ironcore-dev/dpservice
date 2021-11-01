#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_graph.h>
#include <rte_malloc.h>
#include <rte_graph_worker.h>
#include <rte_mbuf.h>
#include "node_api.h"
#include "nodes/tx_node_priv.h"
#include "dp_mbuf_dyn.h"


static struct ethdev_tx_node_main ethdev_tx_main;

static int tx_node_init(const struct rte_graph *graph, struct rte_node *node)
{
	struct tx_node_ctx *ctx = (struct tx_node_ctx *)node->ctx;
	uint64_t port_id = DP_MAX_PORTS;
	uint16_t i;

	/* Find our port id */
	for (i = 0; i < DP_MAX_PORTS; i++) {
		if (ethdev_tx_main.nodes[i] == node->id) {
			port_id = i;
			break;
		}
	}

	RTE_VERIFY(port_id < DP_MAX_PORTS);

	/* Update port and queue */
	ctx->port_id = port_id;
	ctx->queue_id = graph->id;

	return 0;
}

static __rte_always_inline int install_flow(struct rte_mbuf *m)
{
	struct rte_flow_error error;
	struct dp_flow *df;
	struct dp_mbuf_priv1 *dp_mbuf_p1 = NULL;
	struct rte_flow *flow;

	dp_mbuf_p1 = get_dp_mbuf_priv1(m);
	if (!dp_mbuf_p1) {
		printf("Can not get private pointer\n");
		return 0;
	}
	df = dp_mbuf_p1->flow_ptr;
	if (df && df->valid) { 
		flow = rte_flow_create(m->port, &df->attr, df->pattern, df->action, &error);
		if (!flow)
			printf("Flow can't be created message: %s\n", error.message ? error.message : "(no stated reason)");
	}
	rte_free(df);
	return 1;
}  

static __rte_always_inline uint16_t tx_node_process(struct rte_graph *graph,
													struct rte_node *node,
													void **objs,
													uint16_t cnt)
{
	struct tx_node_ctx *ctx = (struct tx_node_ctx *)node->ctx;
	struct rte_mbuf *mbuf0, **pkts;
	uint16_t port, queue;
	uint16_t sent_count, i;

	RTE_SET_USED(objs);
	RTE_SET_USED(cnt);

	/* Get Tx port id */
	port = ctx->port_id;
	queue = ctx->queue_id;

	pkts = (struct rte_mbuf **)objs;


	for (i = 0; i < cnt; i++) {
		mbuf0 = pkts[i];
		/* Offload it to the hardware */
		//printf("node port %d node name %s\n ", ctx->port_id, node->name);
		install_flow(mbuf0);
	}	

	sent_count = rte_eth_tx_burst(port, queue, (struct rte_mbuf **)objs,
				 cnt);

	/* Redirect unsent pkts to drop node */
	if (sent_count != cnt) {
		rte_node_enqueue(graph, node, TX_NEXT_DROP,
				 &objs[sent_count], cnt - sent_count);
	}

	return sent_count;
}

struct ethdev_tx_node_main * tx_node_data_get(void)
{
	return &ethdev_tx_main;
}

static struct rte_node_register tx_node_base = {
	.name = "tx",
	.init = tx_node_init,
	.process = tx_node_process,

	.nb_edges = TX_NEXT_MAX,
	.next_nodes =
		{
			[TX_NEXT_DROP] = "drop",
		},
};

struct rte_node_register *tx_node_get(void)
{
	return &tx_node_base;
}

RTE_NODE_REGISTER(tx_node_base);
