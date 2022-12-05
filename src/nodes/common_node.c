#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include "nodes/common_node.h"

static inline void dp_graphtrace_print_pkt(struct rte_mbuf *pkt, char *buf, size_t bufsize)
{
	struct rte_ether_hdr *frame = rte_pktmbuf_mtod((struct rte_mbuf *)pkt, struct rte_ether_hdr *);

	snprintf(buf, bufsize,
			 RTE_ETHER_ADDR_PRT_FMT " -> " RTE_ETHER_ADDR_PRT_FMT,
			 RTE_ETHER_ADDR_BYTES(&frame->src_addr), RTE_ETHER_ADDR_BYTES(&frame->dst_addr));

	// TODO add more as needed
}

#define GRAPHTRACE_PRINT(PKT, FMT, ...) do { \
	char _graphtrace_buf[512]; \
	dp_graphtrace_print_pkt((PKT), _graphtrace_buf, sizeof(_graphtrace_buf)); \
	DPS_LOG(INFO, GRAPHTRACE, FMT ": %s\n", __VA_ARGS__, _graphtrace_buf); \
} while (0)

#define GRAPHTRACE_PKT_ID(PKT) (PKT)

void dp_graphtrace_burst_next(struct rte_node *node, void **objs, uint16_t nb_objs, rte_edge_t next_index)
{
	if (dp_get_graphtrace_level() < 1)
		return;
	for (uint i = 0; i < nb_objs; ++i)
		GRAPHTRACE_PRINT(objs[i], "%-11s #%u: %p -> %-14s",
						 node->name, i, GRAPHTRACE_PKT_ID(objs[i]), node->nodes[next_index]->name);
}

void dp_graphtrace_burst_tx(struct rte_node *node, void **objs, uint16_t nb_objs, uint16_t port_id)
{
	if (dp_get_graphtrace_level() < 1)
		return;
	for (uint i = 0; i < nb_objs; ++i)
		GRAPHTRACE_PRINT(objs[i], "%-11s #%u: %p >> PORT %-9u",
						 node->name, i, GRAPHTRACE_PKT_ID(objs[i]), port_id);
}

void dp_graphtrace(struct rte_node *node, void *obj)
{
	if (dp_get_graphtrace_level() < 2)
		return;
	GRAPHTRACE_PRINT(obj, "%-14s: %p",
					 node->name, GRAPHTRACE_PKT_ID(obj));
}

void dp_graphtrace_next(struct rte_node *node, void *obj, rte_edge_t next_index)
{
	if (dp_get_graphtrace_level() < 1)
		return;
	GRAPHTRACE_PRINT(obj, "%-14s: %p -> %-14s",
					 node->name, GRAPHTRACE_PKT_ID(obj), node->nodes[next_index]->name);
}
