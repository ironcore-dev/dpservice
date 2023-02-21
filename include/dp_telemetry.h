#ifndef _DP_TELEMETRY_H_
#define _DP_TELEMETRY_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "rte_graph.h"

int dp_telemetry_init(void);
int dp_stats_cb(bool is_first, bool is_last, void *cookie, const struct rte_graph_cluster_node_stats *st);

struct graph_node_stat {
	char name[RTE_NODE_NAMESIZE];
	uint64_t objs;
};

#ifdef __cplusplus
}
#endif

#endif

