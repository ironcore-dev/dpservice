#ifndef __INCLUDE_DP_MBUF_DYN_PRIV_H__
#define __INCLUDE_DP_MBUF_DYN_PRIV_H__

#include "node_api.h"

#ifdef __cplusplus
extern "C" {
#endif

struct dp_flow *get_dp_flow_ptr(struct rte_mbuf *m);
struct dp_flow *alloc_dp_flow_ptr(struct rte_mbuf *m);
struct dp_flow *init_dp_flow_ptr(struct rte_mbuf *m);

#ifdef __cplusplus
}
#endif
#endif
