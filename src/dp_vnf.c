#include "dp_vnf.h"
#include <rte_malloc.h>
#include "dp_error.h"
#include "dp_log.h"
#include "grpc/dp_grpc_responder.h"

static struct rte_hash *vnf_handle_tbl = NULL;

int dp_vnf_init(int socket_id)
{
	vnf_handle_tbl = dp_create_jhash_table(DP_VNF_MAX_TABLE_SIZE, DP_VNF_IPV6_ADDR_SIZE,
										     "vnf_handle_table", socket_id);
	if (!vnf_handle_tbl)
		return DP_ERROR;

	return DP_OK;
}

void dp_vnf_free()
{
	dp_free_jhash_table(vnf_handle_tbl);
}

int dp_set_vnf_value(void *key, struct dp_vnf_value *val)
{
	struct dp_vnf_value *temp_val;

	temp_val = rte_zmalloc("vnf_handle_mapping", sizeof(struct dp_vnf_value), RTE_CACHE_LINE_SIZE);
	if (!temp_val) {
		DPS_LOG_WARNING("vnf handle for port %d malloc data failed\n", val->portid);
		return DP_ERROR;
	}

	RTE_VERIFY(val->portid < DP_MAX_PORTS);
	if (rte_hash_lookup(vnf_handle_tbl, key) >= 0)
		goto err;

	*temp_val = *val;
	if (DP_FAILED(rte_hash_add_key_data(vnf_handle_tbl, key, temp_val))) {
		DPS_LOG_WARNING("vnf handle for port %d add data failed\n", temp_val->portid);
		goto err;
	}
	return DP_OK;

err:
	rte_free(temp_val);
	return DP_ERROR;
}

int dp_get_portid_with_vnf_key(void *key, enum vnf_type v_type)
{
	struct dp_vnf_value *temp_val;
	uint16_t ret_val;

	if (DP_FAILED(rte_hash_lookup_data(vnf_handle_tbl, key, (void **)&temp_val)))
		return DP_ERROR;

	if (temp_val->v_type != v_type)
		return DP_ERROR;

	ret_val = temp_val->portid;

	return ret_val;
}

struct dp_vnf_value *dp_get_vnf_value_with_key(void *key)
{
	struct dp_vnf_value *temp_val;

	if (DP_FAILED(rte_hash_lookup_data(vnf_handle_tbl, key, (void **)&temp_val)))
		return NULL;

	return temp_val;
}

int dp_del_vnf_with_vnf_key(void *key)
{
	struct dp_vnf_value *temp_val;
	int ret;

	ret = rte_hash_lookup_data(vnf_handle_tbl, key, (void **)&temp_val);
	if (DP_FAILED(ret)) {
		DPGRPC_LOG_WARNING("Cannot remove VNF key", DP_LOG_RET(ret));
		return ret;
	}

	rte_free(temp_val);

	ret = rte_hash_del_key(vnf_handle_tbl, key);
	if (DP_FAILED(ret)) {
		DPGRPC_LOG_WARNING("Cannot remove VNF key", DP_LOG_RET(ret));
		return ret;
	}

	return DP_OK;
}

int dp_del_vnf_with_value(struct dp_vnf_value *val)
{
	struct dp_vnf_value *temp_val = NULL;
	uint32_t iter = 0;
	int32_t ret;
	void *key;

	while ((ret = rte_hash_iterate(vnf_handle_tbl, (const void **)&key, (void **)&temp_val, &iter)) != -ENOENT) {
		if (DP_FAILED(ret)) {
			DPS_LOG_ERR("Cannot iterate VNF table %s", dp_strerror(ret));
			return ret;
		}

		if ((val->portid == temp_val->portid)
			&& (val->alias_pfx.ip == temp_val->alias_pfx.ip)
			&& (val->alias_pfx.length == temp_val->alias_pfx.length)
			&& (val->v_type == temp_val->v_type)
		) {
			rte_free(temp_val);
			ret = rte_hash_del_key(vnf_handle_tbl, key);
			if (DP_FAILED(ret)) {
				DPS_LOG_ERR("Cannot delete VNF key %s", dp_strerror(ret));
				return DP_ERROR;
			}
		}
	}
	return DP_OK;
}

int dp_list_vnf_alias_routes(uint16_t portid, enum vnf_type v_type, struct dp_grpc_responder *responder)
{
	void *key;
	struct dp_vnf_value *data;
	uint32_t iter = 0;
	struct dp_route *reply;
	int32_t ret;

	if (rte_hash_count(vnf_handle_tbl) == 0)
		return DP_OK;

	dp_grpc_set_multireply(responder, sizeof(*reply));

	while ((ret = rte_hash_iterate(vnf_handle_tbl, (const void **)&key, (void **)&data, &iter)) != -ENOENT) {
		if (DP_FAILED(ret)) {
			DPS_LOG_ERR("Cannot iterate VNF table %s", dp_strerror(ret));
			return ret;
		}

		if (portid != data->portid || data->v_type != v_type)
			continue;

		reply = dp_grpc_add_reply(responder);
		if (!reply)
			return DP_ERROR;

		reply->pfx_ip_type = RTE_ETHER_TYPE_IPV4;
		reply->pfx_addr = data->alias_pfx.ip;
		reply->pfx_length = data->alias_pfx.length;
		rte_memcpy(reply->trgt_addr6, key, sizeof(reply->trgt_addr6));
	}

	return DP_OK;
}
