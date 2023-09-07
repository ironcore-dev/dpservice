#ifndef __INCLUDE_DP_CNTRACK_H__
#define __INCLUDE_DP_CNTRACK_H__

#include <rte_graph_worker.h>
#include <rte_mbuf.h>

#include "dp_flow.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DP_IS_CAPTURED_HW_PKT  5

void dp_cntrack_init(void);

int dp_cntrack_handle(struct rte_node *node, struct rte_mbuf *m, struct dp_flow *df);

void dp_cntrack_flush_cache(void);

#ifdef __cplusplus
}
#endif


#endif // __INCLUDE_DP_CNTRACK_H__
