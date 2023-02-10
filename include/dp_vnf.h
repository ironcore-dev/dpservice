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

enum vnf_type {
	DP_VNF_TYPE_UNDEFINED,
	DP_VNF_TYPE_LB_ALIAS_PFX,
	DP_VNF_TYPE_ALIAS_PFX,
};

struct dp_vnf_alias {
	uint32_t	ip;
	uint16_t	length;
};

struct dp_vnf_value {
	enum vnf_type	v_type;
	uint32_t		vni;
	uint16_t		portid;
	union {
		struct dp_vnf_alias alias_pfx;
	} vnf;
};

int dp_vnf_init(int socket_id);
int dp_map_vnf_handle(void *key, struct dp_vnf_value *val);
int dp_get_portid_with_vnf_handle(void *key);
void dp_del_portid_with_vnf_handle(struct dp_vnf_value *val);
int dp_list_vnf_alias_routes(struct rte_mbuf *m, uint16_t portid,
								enum vnf_type v_type, struct rte_mbuf *rep_arr[]);

#ifdef __cplusplus
}
#endif
#endif
