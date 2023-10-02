#ifndef __INCLUDE_DP_VNI_H__
#define __INCLUDE_DP_VNI_H__

#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_rib.h>
#include <rte_rib6.h>
#include "dp_refcount.h"
#include "dp_lpm.h"
#include "dp_error.h"
#include "dp_log.h"
#include "grpc/dp_grpc_responder.h"

#ifdef __cplusplus
extern "C" {
#endif

extern struct rte_hash *vni_handle_tbl;

#define DP_VNI_MAX_TABLE_SIZE	512
#define DP_IP_PROTO_IPV4		DP_IP_PROTO_IPv4_ENCAP
#define DP_IP_PROTO_IPV6		DP_IP_PROTO_IPv6_ENCAP

// Protect array access
// Also, when NUMA is not available, DPDK uses SOCKET_ID_ANY (-1)
#define DP_SOCKETID(SOCKETID) (unlikely((unsigned int)(SOCKETID) >= DP_NB_SOCKETS) ? 0 : (SOCKETID))

struct dp_vni_key {
	int vni;
} __rte_packed;

struct dp_vni_data {
	struct rte_rib	*ipv4[DP_NB_SOCKETS];
	struct rte_rib6	*ipv6[DP_NB_SOCKETS];
	struct dp_ref	ref_count;
	int				socket_id;
	int				vni;
};

static __rte_always_inline struct rte_rib *dp_get_vni_route4_table(int vni, int socket_id)
{
	struct dp_vni_data *vni_data;
	struct dp_vni_key vni_key = {
		.vni = vni
	};
	int ret;

	ret = rte_hash_lookup_data(vni_handle_tbl, &vni_key, (void **)&vni_data);
	if (DP_FAILED(ret)) {
		if (ret != -ENOENT)
			DPS_LOG_ERR("VNI lookup error", DP_LOG_VNI(vni), DP_LOG_VNI_TYPE(DP_IP_PROTO_IPV4));
		return NULL;
	}

	return vni_data->ipv4[DP_SOCKETID(socket_id)];
}

static __rte_always_inline struct rte_rib6 *dp_get_vni_route6_table(int vni, int socket_id)
{
	struct dp_vni_data *vni_data;
	struct dp_vni_key vni_key = {
		.vni = vni
	};
	int ret;

	ret = rte_hash_lookup_data(vni_handle_tbl, &vni_key, (void **)&vni_data);
	if (DP_FAILED(ret)) {
		if (ret != -ENOENT)
			DPS_LOG_ERR("VNI lookup error", DP_LOG_VNI(vni), DP_LOG_VNI_TYPE(DP_IP_PROTO_IPV6));
		return NULL;
	}

	return vni_data->ipv6[DP_SOCKETID(socket_id)];
}

int dp_vni_init(int socket_id);
void dp_vni_free(void);
bool dp_is_vni_route_table_available(int vni, int type, int socket_id);
int dp_create_vni_route_tables(int vni, int socket_id);
int dp_delete_vni_route_tables(int vni);
int dp_reset_vni_route_tables(int vni, int socket_id);
int dp_reset_all_vni_route_tables(int socket_id);

#ifdef __cplusplus
}
#endif
#endif
