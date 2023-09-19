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

bool dp_is_vni_route_tbl_available(int vni, int type, int socket_id)
{
	struct dp_vni_data *vni_data;
	struct dp_vni_key vni_key = {
		.vni = vni
	};
	int ret;

	ret = rte_hash_lookup_data(vni_handle_tbl, &vni_key, (void **)&vni_data);
	if (ret == -ENOENT) {
		return false;
	} else if (DP_FAILED(ret)) {
		DPS_LOG_ERR("VNI lookup error", DP_LOG_VNI(vni), DP_LOG_VNI_TYPE(type), DP_LOG_RET(ret));
		return false;
	}

	return (type == DP_IP_PROTO_IPV4 && vni_data->ipv4[DP_SOCKETID(socket_id)])
		|| (type == DP_IP_PROTO_IPV6 && vni_data->ipv6[DP_SOCKETID(socket_id)]);
}

static void dp_free_vni_value(struct dp_ref *ref)
{
	struct dp_vni_data *vni_value = container_of(ref, struct dp_vni_data, ref_count);
	int dp_socketid = DP_SOCKETID(vni_value->socketid);

	DPS_LOG_DEBUG("Freeing VNI", DP_LOG_VNI(vni_value->vni));
	rte_rib_free(vni_value->ipv4[dp_socketid]);
	rte_rib6_free(vni_value->ipv6[dp_socketid]);

	dp_del_all_neigh_nat_entries_in_vni(vni_value->vni);
	rte_free(vni_value);
}

static int dp_create_rib6(const struct dp_vni_key *key, int socket_id, struct dp_vni_data *vni_data)
{
	struct rte_rib6_conf config_ipv6;
	struct rte_rib6 *new_rib6;
	char s[64];

	/* create the LPM table */
	config_ipv6.max_nodes = IPV6_DP_RIB_MAX_RULES;
	config_ipv6.ext_sz = sizeof(struct vm_route);

	snprintf(s, sizeof(s), "IPV6_DP_RIB_%d_%d", key->vni, socket_id);
	new_rib6 = rte_rib6_create(s, socket_id, &config_ipv6);
	if (!new_rib6) {
		DPS_LOG_ERR("Unable to create the DP RIB6 table", DP_LOG_SOCKID(socket_id));
		return DP_ERROR;
	}

	vni_data->ipv6[DP_SOCKETID(socket_id)] = new_rib6;
	vni_data->socketid = socket_id;
	return DP_OK;
}

static int dp_create_rib(const struct dp_vni_key *key, int socket_id, struct dp_vni_data *vni_data)
{
	struct rte_rib_conf config_ipv4;
	struct rte_rib *new_rib;
	char s[64];

	/* create the LPM table */
	config_ipv4.max_nodes = IPV4_DP_RIB_MAX_RULES;
	config_ipv4.ext_sz = sizeof(struct vm_route);

	snprintf(s, sizeof(s), "IPV4_DP_RIB_%d_%d", key->vni, socket_id);
	new_rib = rte_rib_create(s, socket_id, &config_ipv4);
	if (!new_rib) {
		DPS_LOG_ERR("Unable to create the DP RIB table", DP_LOG_SOCKID(socket_id));
		return DP_ERROR;
	}

	vni_data->ipv4[DP_SOCKETID(socket_id)] = new_rib;
	vni_data->socketid = socket_id;
	return DP_OK;
}

int dp_create_vni_route_table(int vni, int type, int socket_id)
{
	struct dp_vni_data *vni_data;
	struct dp_vni_key vni_key = {
		.vni = vni
	};
	int ret;

	ret = rte_hash_lookup_data(vni_handle_tbl, &vni_key, (void **)&vni_data);
	if (ret == -ENOENT) {
		vni_data = rte_zmalloc("vni_handle_table", sizeof(struct dp_vni_data), RTE_CACHE_LINE_SIZE);
		if (!vni_data) {
			DPS_LOG_ERR("VNI allocation failed", DP_LOG_VNI(vni), DP_LOG_VNI_TYPE(type));
			return DP_ERROR;
		}
		if (type == DP_IP_PROTO_IPV4) {
			if (DP_FAILED(dp_create_rib(&vni_key, socket_id, vni_data)))
				goto err_free;
		} else if (type == DP_IP_PROTO_IPV6) {
			if (DP_FAILED(dp_create_rib6(&vni_key, socket_id, vni_data)))
				goto err_free;
		} else {
			goto err_free;
		}
		ret = rte_hash_add_key_data(vni_handle_tbl, &vni_key, vni_data);
		if (DP_FAILED(ret)) {
			DPS_LOG_WARNING("Failed to add to route4 hashtable", DP_LOG_VNI(vni), DP_LOG_VNI_TYPE(type), DP_LOG_RET(ret));
			return DP_ERROR;
		}
		vni_data->vni = vni;
		dp_ref_init(&vni_data->ref_count, dp_free_vni_value);
	} else if (DP_FAILED(ret)) {
		DPS_LOG_ERR("VNI creation error", DP_LOG_VNI(vni), DP_LOG_VNI_TYPE(type), DP_LOG_RET(ret));
		return DP_ERROR;
	} else {
		if ((type == DP_IP_PROTO_IPV4) && !vni_data->ipv4[DP_SOCKETID(socket_id)]) {
			if (DP_FAILED(dp_create_rib(&vni_key, socket_id, vni_data)))
				goto err;
		}
		if (type == DP_IP_PROTO_IPV6 && !vni_data->ipv6[DP_SOCKETID(socket_id)]) {
			if (DP_FAILED(dp_create_rib6(&vni_key, socket_id, vni_data)))
				goto err;
		}
		dp_ref_inc(&vni_data->ref_count);
	}

	return DP_OK;
err_free:
	rte_free(vni_data);
err:
	DPS_LOG_ERR("VNI creation failed", DP_LOG_VNI(vni), DP_LOG_VNI_TYPE(type));
	return DP_ERROR;
}

int dp_delete_vni_route_table(int vni, int type)
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

int dp_reset_vni_route_table(int vni, int type, int socket_id)
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

	if (type == DP_IP_PROTO_IPV4) {
		if (vni_data->ipv4[DP_SOCKETID(socket_id)]) {
			rte_rib_free(vni_data->ipv4[DP_SOCKETID(socket_id)]);
			if (DP_FAILED(dp_create_rib(&vni_key, socket_id, vni_data)))
				return DP_ERROR;
		} else {
			return DP_ERROR;
		}
	} else if (type == DP_IP_PROTO_IPV6) {
		if (vni_data->ipv6[DP_SOCKETID(socket_id)]) {
			rte_rib6_free(vni_data->ipv6[DP_SOCKETID(socket_id)]);
			if (DP_FAILED(dp_create_rib6(&vni_key, socket_id, vni_data)))
				return DP_ERROR;
		} else {
			return DP_ERROR;
		}
	} else {
		return DP_ERROR;
	}

	return DP_OK;
}

int dp_reset_vni_all_route_tables(int socket_id)
{
	struct dp_vni_data *vni_data;
	const struct dp_vni_key *key;
	uint32_t iter = 0;
	int32_t ret;

	if (rte_hash_count(vni_handle_tbl) == 0)
		return DP_OK;

	while ((ret = rte_hash_iterate(vni_handle_tbl, (const void **)&key, (void **)&vni_data, &iter)) != -ENOENT) {
		if (vni_data->ipv4[DP_SOCKETID(socket_id)]) {
			rte_rib_free(vni_data->ipv4[DP_SOCKETID(socket_id)]);
			if (DP_FAILED(dp_create_rib(key, socket_id, vni_data)))
				return DP_ERROR;
		}
		if (vni_data->ipv6[DP_SOCKETID(socket_id)]) {
			rte_rib6_free(vni_data->ipv6[DP_SOCKETID(socket_id)]);
			if (DP_FAILED(dp_create_rib6(key, socket_id, vni_data)))
				return DP_ERROR;
		}
	}

	return DP_OK;
}
