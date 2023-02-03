#ifndef __INCLUDE_DP_VNF_H__
#define __INCLUDE_DP_VNF_H__

#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_flow.h>
#include "dpdk_layer.h"
#include "grpc/dp_grpc_impl.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DP_VNF_MAX_TABLE_SIZE 100
#define DP_VNF_IPV6_ADDR_SIZE 16

typedef struct dp_vnf_value {
	uint32_t ip;
	uint16_t portid;
	uint16_t length;
} dp_vnf_value;

int dp_vnf_init(int socket_id);
int dp_map_vnf_handle(void *key, dp_vnf_value *val);
int dp_get_portid_with_vnf_handle(void *key);
void dp_del_portid_with_vnf_handle(dp_vnf_value *val);
int dp_list_vnf_routes(struct rte_mbuf *m, uint16_t portid,
						 struct rte_mbuf *rep_arr[]);

#ifdef __cplusplus
}
#endif
#endif
