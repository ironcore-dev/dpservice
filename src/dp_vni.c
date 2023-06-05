#include <rte_malloc.h>
#include "dp_vni.h"
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

void dp_vni_free()
{
	dp_free_jhash_table(vni_handle_tbl);
}

bool dp_is_vni_route_tbl_available(int vni, int type, int socketid)
{
	struct dp_vni_value *temp_val = NULL;
	struct dp_vni_key vni_key;
	int ret;

	vni_key.type = type;
	vni_key.vni = vni;

	ret = rte_hash_lookup_data(vni_handle_tbl, &vni_key, (void **)&temp_val);

	if (ret == -ENOENT) {
		return false;
	} else if (DP_FAILED(ret)) {
		DPS_LOG_ERR("vni %d type %d lookup error", vni, type);
		return false;
	}

	if (temp_val->ipv4[socketid] && (type == DP_IP_PROTO_IPV4))
		return true;

	if (temp_val->ipv6[socketid] && (type == DP_IP_PROTO_IPV6))
		return true;

	return false;
}

static void dp_free_vni_value(struct dp_ref *ref)
{
	struct dp_vni_value *vni_value = container_of(ref, struct dp_vni_value, ref_count);

	DPS_LOG_DEBUG("Freeing route table for VNI %d", vni_value->vni);
	if (vni_value->ipv4[vni_value->socketid])
		rte_rib_free(vni_value->ipv4[vni_value->socketid]);

	if (vni_value->ipv6[vni_value->socketid])
		rte_rib6_free(vni_value->ipv6[vni_value->socketid]);

	dp_del_all_neigh_nat_entries_in_vni(vni_value->vni);
	rte_free(vni_value);
}

static __rte_always_inline int dp_create_rib6(struct dp_vni_key *key, int socketid, struct dp_vni_value *temp_val)
{
	struct rte_rib6_conf config_ipv6;
	char s[64];

	/* create the LPM table */
	config_ipv6.max_nodes = IPV6_DP_RIB_MAX_RULES;
	config_ipv6.ext_sz = sizeof(struct vm_route);

	snprintf(s, sizeof(s), "IPV6_DP_RIB_%d_%d", key->vni, socketid);
	temp_val->ipv6[socketid] = rte_rib6_create(s, socketid, &config_ipv6);
	if (!temp_val->ipv6[socketid]) {
		DPS_LOG_ERR("Unable to create the DP RIB table on socket %d", socketid);
		return DP_ERROR;
	}
	temp_val->socketid = socketid;
	return DP_OK;
}

static __rte_always_inline int dp_create_rib(struct dp_vni_key *key, int socketid, struct dp_vni_value *temp_val)
{
	struct rte_rib_conf config_ipv4;
	char s[64];

	/* create the LPM table */
	config_ipv4.max_nodes = IPV4_DP_RIB_MAX_RULES;
	config_ipv4.ext_sz = sizeof(struct vm_route);

	snprintf(s, sizeof(s), "IPV4_DP_RIB_%d_%d", key->vni, socketid);
	temp_val->ipv4[socketid] = rte_rib_create(s, socketid, &config_ipv4);
	if (!temp_val->ipv4[socketid]) {
		DPS_LOG_ERR("Unable to create the DP RIB table on socket %d", socketid);
		return DP_ERROR;
	}
	temp_val->socketid = socketid;
	return DP_OK;
}

int dp_create_vni_route_table(int vni, int type, int socketid)
{
	struct dp_vni_value *temp_val = NULL;
	struct dp_vni_key vni_key;
	int ret;

	vni_key.type = type;
	vni_key.vni = vni;

	ret = rte_hash_lookup_data(vni_handle_tbl, &vni_key, (void **)&temp_val);

	if (ret == -ENOENT) {
		temp_val = rte_zmalloc("vni_handle_table", sizeof(struct dp_vni_value), RTE_CACHE_LINE_SIZE);
		if (!temp_val) {
			DPS_LOG_ERR("vni %d creation malloc failed", vni);
			return DP_ERROR;
		}
		if (type == DP_IP_PROTO_IPV4) {
			if (DP_FAILED(dp_create_rib(&vni_key, socketid, temp_val)))
				goto err;
		} else if (type == DP_IP_PROTO_IPV6) {
			if (DP_FAILED(dp_create_rib6(&vni_key, socketid, temp_val)))
				goto err;
		} else {
			goto err;
		}
		ret = rte_hash_add_key_data(vni_handle_tbl, &vni_key, temp_val);
		if (DP_FAILED(ret)) {
			DPS_LOG_WARNING("vni %d route4 hashtable addition failed %s", vni, dp_strerror(ret));
			return DP_ERROR;
		}
		temp_val->vni = vni;
		dp_ref_init(&temp_val->ref_count, dp_free_vni_value);
	} else if (DP_FAILED(ret)) {
		DPS_LOG_ERR("vni %d creation error %s", vni, dp_strerror(ret));
		return DP_ERROR;
	} else {
		if ((type == DP_IP_PROTO_IPV4) && !temp_val->ipv4[socketid]) {
			if (DP_FAILED(dp_create_rib(&vni_key, socketid, temp_val)))
				goto err2;
		}
		if (type == DP_IP_PROTO_IPV6 && !temp_val->ipv6[socketid]) {
			if (DP_FAILED(dp_create_rib6(&vni_key, socketid, temp_val)))
				goto err2;
		}
		dp_ref_inc(&temp_val->ref_count);
	}

	return DP_OK;
err:
	rte_free(temp_val);
err2:
	DPS_LOG_ERR("vni %d creation type %d failed", vni, type);
	return DP_ERROR;
}

int dp_delete_vni_route_table(int vni, int type)
{
	struct dp_vni_value *temp_val = NULL;
	struct dp_vni_key vni_key;

	vni_key.type = type;
	vni_key.vni = vni;

	if (DP_FAILED(rte_hash_lookup_data(vni_handle_tbl, &vni_key, (void **)&temp_val)))
		return DP_ERROR;

	if (dp_ref_dec_and_chk_freed(&temp_val->ref_count))
		if (DP_FAILED(rte_hash_del_key(vni_handle_tbl, &vni_key)))
			return DP_ERROR;

	return DP_OK;
}

int dp_reset_vni_route_table(int vni, int type, int socketid)
{
	struct dp_vni_value *temp_val = NULL;
	struct dp_vni_key vni_key = {
		.type = type,
		.vni = vni
	};

	if (DP_FAILED(rte_hash_lookup_data(vni_handle_tbl, &vni_key, (void **)&temp_val)))
		return DP_OK;

	if (type == DP_IP_PROTO_IPV4) {
		if (temp_val->ipv4[socketid]) {
			rte_rib_free(temp_val->ipv4[socketid]);
			if (DP_FAILED(dp_create_rib(&vni_key, socketid, temp_val)))
				return DP_ERROR;
		} else {
			return DP_ERROR;
		}
	} else if (type == DP_IP_PROTO_IPV6) {
		if (temp_val->ipv6[socketid]) {
			rte_rib6_free(temp_val->ipv6[socketid]);
			if (DP_FAILED(dp_create_rib6(&vni_key, socketid, temp_val)))
				return DP_ERROR;
		} else {
			return DP_ERROR;
		}
	} else {
		return DP_ERROR;
	}

	return DP_OK;
}

int dp_reset_vni_all_route_tables(int socketid)
{
	struct dp_vni_value *temp_val = NULL;
	struct dp_vni_key *key;
	uint32_t iter = 0;
	int32_t ret;

	if (rte_hash_count(vni_handle_tbl) == 0)
		return DP_OK;

	while ((ret = rte_hash_iterate(vni_handle_tbl, (const void **)&key, (void **)&temp_val, &iter)) != -ENOENT) {
		if (temp_val->ipv4[socketid]) {
			rte_rib_free(temp_val->ipv4[socketid]);
			if (DP_FAILED(dp_create_rib(key, socketid, temp_val)))
				return DP_ERROR;
		}
		if (temp_val->ipv6[socketid]) {
			rte_rib6_free(temp_val->ipv6[socketid]);
			if (DP_FAILED(dp_create_rib6(key, socketid, temp_val)))
				return DP_ERROR;
		}
	}

	return DP_OK;
}
