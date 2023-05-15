#ifndef __INCLUDE_DP_VNI_H__
#define __INCLUDE_DP_VNI_H__

#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_rib.h>
#include <rte_rib6.h>
#include "dpdk_layer.h"
#include "dp_refcount.h"
#include "dp_lpm.h"
#include "dp_error.h"
#include "dp_log.h"
#include "grpc/dp_grpc_impl.h"

#ifdef __cplusplus
extern "C" {
#endif

extern struct rte_hash *vni_handle_tbl;

#define DP_VNI_MAX_TABLE_SIZE	512
#define DP_IP_PROTO_IPV4		DP_IP_PROTO_IPv4_ENCAP
#define DP_IP_PROTO_IPV6		DP_IP_PROTO_IPv6_ENCAP

struct dp_vni_key {
	int vni;
	int type;
};

struct dp_vni_value {
	struct rte_rib	*ipv4[DP_NB_SOCKETS];
	struct rte_rib6	*ipv6[DP_NB_SOCKETS];
	struct dp_ref	ref_count;
	int				socketid;
	int				vni;
};

static __rte_always_inline struct rte_rib *dp_get_vni_route4_table(int vni, int socketid)
{
	struct dp_vni_value *temp_val = NULL;
	struct dp_vni_key vni_key;
	int ret;

	vni_key.type = DP_IP_PROTO_IPV4;
	vni_key.vni = vni;

	ret = rte_hash_lookup_data(vni_handle_tbl, &vni_key, (void **)&temp_val);
	if (DP_FAILED(ret)) {
		if (ret != -ENOENT)
			DPS_LOG_ERR("vni %d type %d lookup error", vni, DP_IP_PROTO_IPV4);
		return NULL;
	}

	if (!temp_val->ipv4[socketid])
		return NULL;

	return temp_val->ipv4[socketid];
}

static __rte_always_inline struct rte_rib6 *dp_get_vni_route6_table(int vni, int socketid)
{
	struct dp_vni_value *temp_val = NULL;
	struct dp_vni_key vni_key;
	int ret;

	vni_key.type = DP_IP_PROTO_IPV6;
	vni_key.vni = vni;

	ret = rte_hash_lookup_data(vni_handle_tbl, &vni_key, (void **)&temp_val);
	if (DP_FAILED(ret)) {
		if (ret != -ENOENT)
			DPS_LOG_ERR("vni %d type %d lookup error", vni, DP_IP_PROTO_IPV6);
		return NULL;
	}

	if (!temp_val->ipv6[socketid])
		return NULL;

	return temp_val->ipv6[socketid];
}

int dp_vni_init(int socket_id);
void dp_vni_free();
bool dp_is_vni_route_tbl_available(int vni, int type, int socketid);
int dp_create_vni_route_table(int vni, int type, int socketid);
int dp_delete_vni_route_table(int vni, int type);
int dp_reset_vni_route_table(int vni, int type, int socketid);
int dp_reset_vni_all_route_tables(int socketid);

#ifdef __cplusplus
}
#endif
#endif