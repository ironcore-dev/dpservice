#ifndef __INCLUDE_DP_CNTRACK_H__
#define __INCLUDE_DP_CNTRACK_H__

#include <rte_common.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_mbuf.h>

#include "dp_flow.h"

#ifdef __cplusplus
extern "C" {
#endif

int dp_cntrack_handle(struct rte_node *node, struct rte_mbuf *m, struct dp_flow *df);


#ifdef __cplusplus
}
#endif


#endif // __INCLUDE_DP_CNTRACK_H__
