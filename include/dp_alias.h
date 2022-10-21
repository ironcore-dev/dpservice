#ifndef __INCLUDE_DP_ALIAS_H__
#define __INCLUDE_DP_ALIAS_H__

#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_flow.h>
#include "dpdk_layer.h"
#include "grpc/dp_grpc_impl.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DP_ALIAS_MAX_TABLE_SIZE 100
#define DP_ALIAS_IPV6_ADDR_SIZE 16

typedef struct dp_alias_value {
	uint32_t ip;
	uint16_t portid;
	uint16_t length;
} dp_alias_value;

void dp_init_alias_handle_tbl(int socket_id);
int dp_map_alias_handle(void *key, dp_alias_value *val);
int dp_get_portid_with_alias_handle(void *key);
void dp_del_portid_with_alias_handle(dp_alias_value *val);
int dp_list_alias_routes(struct rte_mbuf *m, uint16_t portid,
						 struct rte_mbuf *rep_arr[]);

#ifdef __cplusplus
}
#endif
#endif