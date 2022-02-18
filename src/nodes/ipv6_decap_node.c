#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_mbuf.h>
#include "node_api.h"
#include "nodes/ipv6_decap_node.h"
#include "dp_mbuf_dyn.h"
#include "dp_lpm.h"
#include "dp_rte_flow.h"

struct ipv6_decap_node_main ipv6_decap_node;

static int ipv6_decap_node_init(const struct rte_graph *graph, struct rte_node *node)
{
	struct ipv6_decap_node_ctx *ctx = (struct ipv6_decap_node_ctx *)node->ctx;

	ctx->next = IPV6_DECAP_NEXT_DROP;


	RTE_SET_USED(graph);

	return 0;
}

static __rte_always_inline int handle_ipv6_decap(struct rte_mbuf *m)
{
	/* Pop the ipv6 header */
	rte_pktmbuf_adj(m, (uint16_t)sizeof(struct rte_ipv6_hdr));
	return 1;
} 

static __rte_always_inline uint16_t ipv6_decap_node_process(struct rte_graph *graph,
													 struct rte_node *node,
													 void **objs,
													 uint16_t cnt)
{
	struct rte_mbuf *mbuf0, **pkts;
	struct dp_flow *df;
	int i;


	pkts = (struct rte_mbuf **)objs;

	for (i = 0; i < cnt; i++) {
		mbuf0 = pkts[i];
		df = get_dp_flow_ptr(mbuf0);
		if (handle_ipv6_decap(mbuf0)) {

				df->flags.flow_type=DP_FLOW_TYPE_INCOMING;
				rte_node_enqueue_x1(graph, node, IPV6_DECAP_NEXT_SRV6_DECAP, mbuf0);
		
		}
		else {
			rte_node_enqueue_x1(graph, node, IPV6_DECAP_NEXT_DROP, mbuf0);
		}
	}	

	return cnt;
}

int ipv6_decap_set_next(uint16_t port_id, uint16_t next_index)
{

	ipv6_decap_node.next_index[port_id] = next_index;
	return 0;
}

static struct rte_node_register ipv6_decap_node_base = {
	.name = "ipv6_decap",
	.init = ipv6_decap_node_init,
	.process = ipv6_decap_node_process,

	.nb_edges = IPV6_DECAP_NEXT_MAX,
	.next_nodes =
		{
			[IPV6_DECAP_NEXT_DROP] = "drop",
			[IPV6_DECAP_NEXT_SRV6_DECAP] = "srv6_decap",
		},
};

struct rte_node_register *ipv6_decap_node_get(void)
{
	return &ipv6_decap_node_base;
}

RTE_NODE_REGISTER(ipv6_decap_node_base);
