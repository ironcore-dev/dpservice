#ifndef __INCLUDE_DP_RTE_FLOW_TRAFFIC_FORWARD_H
#define __INCLUDE_DP_RTE_FLOW_TRAFFIC_FORWARD_H

#ifdef __cplusplus
extern "C"
{
#endif


#include <unistd.h>
#include "rte_malloc.h"
#include "dp_rte_flow.h"
#include "nodes/ipv6_nd_node.h"

#define DP_TUNN_OPS_OFFLOAD_MAX_PATTERN 7
#define DP_TUNN_OPS_OFFLOAD_MAX_ACTION 8

#define DP_TUNN_IPIP_ENCAP_SIZE sizeof(struct rte_ether_hdr)+sizeof(struct rte_ipv6_hdr)

int dp_handle_traffic_forward_offloading(struct rte_mbuf *m,struct dp_flow *df);

#ifdef __cplusplus
}
#endif



#endif /* __INCLUDE_DP_RTE_FLOW_TRAFFIC_FORWARD_H */
