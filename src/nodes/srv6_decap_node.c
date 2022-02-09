#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_mbuf.h>
#include "node_api.h"
#include "dp_mbuf_dyn.h"
#include "dp_lpm.h"
#include "dpdk_layer.h"

#include "nodes/srv6_common.h"
#include "nodes/srv6_decap_node.h"


struct srv6_decap_node_main srv6_decap_node;

static int srv6_decap_node_init(const struct rte_graph *graph, struct rte_node *node)
{
	struct srv6_decap_node_ctx *ctx = (struct srv6_decap_node_ctx *)node->ctx;

	ctx->next = SRV6_DECAP_NEXT_DROP;


	RTE_SET_USED(graph);

	return 0;
}

static __rte_always_inline int handle_srv6_decap(struct rte_mbuf *m)
{
	uint8_t route;
	struct segment_routing_hdr *srv6_hdr;
	struct dp_flow *df;
	
	srv6_hdr = rte_pktmbuf_mtod(m, struct segment_routing_hdr*);
	df = get_dp_flow_ptr(m);

	memcpy(&df->dst_vni,srv6_hdr->last_segment.function,4);

	if (srv6_hdr->next_hdr == DP_IP_PROTO_IPv4_ENCAP){
		rte_pktmbuf_adj(m, (uint16_t)sizeof(struct segment_routing_hdr));
		route = SRV6_DECAP_NEXT_IPV4_LOOKUP;

	}
	else{
		route = SRV6_DECAP_NEXT_IPV6_LOOKUP;

	}


	return route;
} 

static __rte_always_inline uint16_t srv6_decap_node_process(struct rte_graph *graph,
													 struct rte_node *node,
													 void **objs,
													 uint16_t cnt)
{
	struct rte_mbuf *mbuf0, **pkts;
	int i;
	uint8_t ret;

	pkts = (struct rte_mbuf **)objs;


	for (i = 0; i < cnt; i++) {
		mbuf0 = pkts[i];
		ret = handle_srv6_decap(mbuf0);
		if (ret > 0)
			rte_node_enqueue_x1(graph, node, ret, mbuf0);
		else
			rte_node_enqueue_x1(graph, node, SRV6_DECAP_NEXT_DROP, mbuf0);
	}	

    return cnt;
}

// int srv6_decap_set_next(uint16_t port_id, uint16_t next_index)
// {
// 	srv6_decap_node.next_index[port_id] = next_index;
// 	return 0;
// }

static struct rte_node_register srv6_decap_node_base = {
	.name = "srv6_decap",
	.init = srv6_decap_node_init,
	.process = srv6_decap_node_process,

	.nb_edges = SRV6_DECAP_NEXT_MAX,
	.next_nodes =
		{
			[SRV6_DECAP_NEXT_DROP] = "drop",
			[SRV6_DECAP_NEXT_IPV4_LOOKUP] = "ipv4_lookup",
			[SRV6_DECAP_NEXT_IPV6_LOOKUP] = "ipv6_lookup",
		},
};

struct rte_node_register *srv6_decap_node_get(void)
{
	return &srv6_decap_node_base;
}

RTE_NODE_REGISTER(srv6_decap_node_base);