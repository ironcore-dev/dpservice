#ifndef __INCLUDE_DP_MBUF_DYN_PRIV_H__
#define __INCLUDE_DP_MBUF_DYN_PRIV_H__

#include "node_api.h"

#ifdef __cplusplus
extern "C" {
#endif

int rte_mbuf_dyn_flow_register();
struct dp_mbuf_priv1 *get_dp_mbuf_priv1(struct rte_mbuf *m);
struct dp_flow * get_dp_flow_ptr(struct rte_mbuf *m);
struct dp_flow * alloc_dp_flow_ptr(struct rte_mbuf *m);
void init_dp_mbuf_priv1(struct rte_mbuf *m);
#ifdef __cplusplus
}
#endif
#endif