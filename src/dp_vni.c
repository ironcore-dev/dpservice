// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#include "dp_vni.h"
#include <rte_malloc.h>
#include "dp_error.h"
#include "dp_nat.h"

struct rte_hash *vni_handle_tbl = NULL;

int dp_vni_init(int socket_id)
{
	vni_handle_tbl = dp_create_jhash_table(DP_VNI_MAX_TABLE_SIZE, sizeof(struct dp_vni_key),
										     "vni_handle_table", socket_id);
	if (!vni_handle_tbl)
		return DP_ERROR;

	return DP_OK;
}

void dp_vni_free(void)
{
	dp_free_jhash_table(vni_handle_tbl);
}

bool dp_is_vni_route_table_available(uint32_t vni, int type)
{
	struct dp_vni_data *vni_data;
	struct dp_vni_key vni_key = {
		.vni = vni
	};
	int ret;

	ret = rte_hash_lookup_data(vni_handle_tbl, &vni_key, (void **)&vni_data);
	if (DP_FAILED(ret)) {
		if (ret != -ENOENT)
			DPS_LOG_ERR("VNI lookup error", DP_LOG_VNI(vni), DP_LOG_RET(ret));
		return false;
	}

	return (type == DP_IP_PROTO_IPV4 && vni_data->ipv4[DP_SOCKETID(vni_data->socket_id)])
		|| (type == DP_IP_PROTO_IPV6 && vni_data->ipv6[DP_SOCKETID(vni_data->socket_id)]);
}

static __rte_always_inline void dp_free_rib6(struct dp_vni_data *vni_data)
{
	rte_rib6_free(vni_data->ipv6[DP_SOCKETID(vni_data->socket_id)]);
}

static __rte_always_inline void dp_free_rib(struct dp_vni_data *vni_data)
{
	rte_rib_free(vni_data->ipv4[DP_SOCKETID(vni_data->socket_id)]);
}

static void dp_free_vni_data(struct dp_ref *ref)
{
	struct dp_vni_data *vni_data = container_of(ref, struct dp_vni_data, ref_count);

	DPS_LOG_DEBUG("Freeing VNI", DP_LOG_VNI(vni_data->vni));
	dp_free_rib6(vni_data);
	dp_free_rib(vni_data);

	dp_del_all_neigh_nat_entries_in_vni(vni_data->vni);
	rte_free(vni_data);
}

static __rte_always_inline int dp_create_rib6(uint32_t vni, int socket_id, struct dp_vni_data *vni_data)
{
	struct rte_rib6_conf config_ipv6;
	struct rte_rib6 *new_rib6;
	char s[64];

	config_ipv6.max_nodes = IPV6_DP_RIB_MAX_RULES;
	config_ipv6.ext_sz = sizeof(struct dp_iface_route);

	snprintf(s, sizeof(s), "IPV6_DP_RIB_%d_%d", vni, socket_id);
	new_rib6 = rte_rib6_create(s, socket_id, &config_ipv6);
	if (!new_rib6) {
		DPS_LOG_ERR("Unable to create DP RIB6 table", DP_LOG_SOCKID(socket_id));
		return DP_ERROR;
	}

	vni_data->vni = vni;
	vni_data->socket_id = socket_id;
	vni_data->ipv6[DP_SOCKETID(socket_id)] = new_rib6;
	return DP_OK;
}

static __rte_always_inline int dp_create_rib(uint32_t vni, int socket_id, struct dp_vni_data *vni_data)
{
	struct rte_rib_conf config_ipv4;
	struct rte_rib *new_rib;
	char s[64];

	config_ipv4.max_nodes = IPV4_DP_RIB_MAX_RULES;
	config_ipv4.ext_sz = sizeof(struct dp_iface_route);

	snprintf(s, sizeof(s), "IPV4_DP_RIB_%d_%d", vni, socket_id);
	new_rib = rte_rib_create(s, socket_id, &config_ipv4);
	if (!new_rib) {
		DPS_LOG_ERR("Unable to create DP RIB table", DP_LOG_SOCKID(socket_id));
		return DP_ERROR;
	}

	vni_data->vni = vni;
	vni_data->socket_id = socket_id;
	vni_data->ipv4[DP_SOCKETID(socket_id)] = new_rib;
	return DP_OK;
}

static __rte_always_inline int dp_allocate_vni_route_tables(const struct dp_vni_key *vni_key, int socket_id)
{
	struct dp_vni_data *vni_data;
	uint32_t vni = vni_key->vni;
	int ret;

	vni_data = rte_zmalloc("vni_handle_table", sizeof(struct dp_vni_data), RTE_CACHE_LINE_SIZE);
	if (!vni_data) {
		DPS_LOG_ERR("VNI allocation failed", DP_LOG_VNI(vni));
		goto err_alloc;
	}

	if (DP_FAILED(dp_create_rib(vni, socket_id, vni_data)))
		goto err_rib;

	if (DP_FAILED(dp_create_rib6(vni, socket_id, vni_data)))
		goto err_rib6;

	ret = rte_hash_add_key_data(vni_handle_tbl, vni_key, vni_data);
	if (DP_FAILED(ret)) {
		DPS_LOG_WARNING("Failed to add to VNI hashtable", DP_LOG_VNI(vni), DP_LOG_RET(ret));
		goto err_hash;
	}

	dp_ref_init(&vni_data->ref_count, dp_free_vni_data);
	return DP_OK;

err_hash:
	dp_free_rib6(vni_data);
err_rib6:
	dp_free_rib(vni_data);
err_rib:
	rte_free(vni_data);
err_alloc:
	DPS_LOG_ERR("VNI creation failed", DP_LOG_VNI(vni));
	return DP_ERROR;
}

int dp_create_vni_route_tables(uint32_t vni, int socket_id)
{
	struct dp_vni_data *vni_data;
	struct dp_vni_key vni_key = {
		.vni = vni
	};
	int ret;

	ret = rte_hash_lookup_data(vni_handle_tbl, &vni_key, (void **)&vni_data);
	if (DP_FAILED(ret)) {
		if (ret != -ENOENT) {
			DPS_LOG_ERR("VNI creation error", DP_LOG_VNI(vni), DP_LOG_RET(ret));
			return DP_ERROR;
		}
		return dp_allocate_vni_route_tables(&vni_key, socket_id);
	}

	dp_ref_inc(&vni_data->ref_count);
	return DP_OK;

}

int dp_delete_vni_route_tables(uint32_t vni)
{
	struct dp_vni_data *vni_data;
	struct dp_vni_key vni_key = {
		.vni = vni
	};
	int ret;

	ret = rte_hash_lookup_data(vni_handle_tbl, &vni_key, (void **)&vni_data);
	if (DP_FAILED(ret)) {
		DPS_LOG_ERR("Cannot lookup VNI data", DP_LOG_RET(ret));
		return ret;
	}

	if (dp_ref_dec_and_chk_freed(&vni_data->ref_count)) {
		ret = rte_hash_del_key(vni_handle_tbl, &vni_key);
		if (DP_FAILED(ret)) {
			DPS_LOG_ERR("Cannot delete VNI key", DP_LOG_RET(ret));
			return DP_ERROR;
		}
	}

	return DP_OK;
}

static int dp_reset_vni_data(uint32_t vni, struct dp_vni_data *vni_data)
{
	int socket_id = DP_SOCKETID(vni_data->socket_id);

	if (vni_data->ipv4[socket_id]) {
		rte_rib_free(vni_data->ipv4[socket_id]);
		if (DP_FAILED(dp_create_rib(vni, socket_id, vni_data)))
			return DP_ERROR;
	}

	if (vni_data->ipv6[socket_id]) {
		rte_rib6_free(vni_data->ipv6[socket_id]);
		if (DP_FAILED(dp_create_rib6(vni, socket_id, vni_data)))
			return DP_ERROR;
	}

	return DP_OK;
}

int dp_reset_vni_route_tables(uint32_t vni)
{
	struct dp_vni_data *vni_data;
	struct dp_vni_key vni_key = {
		.vni = vni
	};
	int ret;

	ret = rte_hash_lookup_data(vni_handle_tbl, &vni_key, (void **)&vni_data);
	if (DP_FAILED(ret)) {
		DPS_LOG_ERR("Cannot lookup VNI data", DP_LOG_RET(ret));
		return DP_OK;
	}

	return dp_reset_vni_data(vni, vni_data);
}

int dp_reset_all_vni_route_tables(void)
{
	struct dp_vni_data *vni_data;
	const struct dp_vni_key *vni_key;
	uint32_t iter = 0;
	int32_t ret;

	if (rte_hash_count(vni_handle_tbl) == 0)
		return DP_OK;

	while ((ret = rte_hash_iterate(vni_handle_tbl, (const void **)&vni_key, (void **)&vni_data, &iter)) != -ENOENT) {
		if (DP_FAILED(dp_reset_vni_data(vni_key->vni, vni_data)))
			return DP_ERROR;
	}

	return DP_OK;
}
