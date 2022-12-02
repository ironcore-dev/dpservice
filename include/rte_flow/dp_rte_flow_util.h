#ifndef __INCLUDE_DP_RTE_FLOW_UTIL_H
#define __INCLUDE_DP_RTE_FLOW_UTIL_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <unistd.h>
#include "rte_malloc.h"
#include "dp_rte_flow.h"


int dp_install_protection_drop(struct rte_mbuf *m, struct dp_flow *df);


#ifdef __cplusplus
}
#endif

#endif /* __INCLUDE_DP_RTE_FLOW_UTIL_H */