#include "dp_vnf.h"
#include <rte_malloc.h>
#include "dp_error.h"
#include "dp_log.h"
#include "dp_lpm.h"
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

void dp_vnf_free(void)
{
	dp_free_jhash_table(vnf_handle_tbl);
}

int dp_set_vnf_value(const uint8_t ul_addr6[DP_VNF_IPV6_ADDR_SIZE], const struct dp_vnf_value *val)
{
	struct dp_vnf_value *temp_val;
	int ret;

	temp_val = rte_zmalloc("vnf_handle_mapping", sizeof(struct dp_vnf_value), RTE_CACHE_LINE_SIZE);
	if (!temp_val) {
		DPS_LOG_WARNING("VNF handle allocation failed", DP_LOG_PORTID(val->portid));
		return DP_ERROR;
	}

	if (rte_hash_lookup(vnf_handle_tbl, ul_addr6) >= 0)
		goto err;

	*temp_val = *val;
	ret = rte_hash_add_key_data(vnf_handle_tbl, ul_addr6, temp_val);
	if (DP_FAILED(ret)) {
		DPS_LOG_WARNING("VNF handle addition failed", DP_LOG_PORTID(temp_val->portid), DP_LOG_RET(ret));
		goto err;
	}
	return DP_OK;

err:
	rte_free(temp_val);
	return DP_ERROR;
}

int dp_get_vnf_entry(struct dp_vnf_value *val, enum vnf_type v_type, const struct dp_port *port, bool match_all)
{
	val->v_type = v_type;
	val->portid = match_all ? DP_VNF_MATCH_ALL_PORT_ID_VALUE : port->port_id;
	val->vni = port->iface.vni;
	return dp_find_vnf_with_value(val);
}

const struct dp_vnf_value *dp_get_vnf_value(const uint8_t ul_addr6[DP_VNF_IPV6_ADDR_SIZE])
{
	struct dp_vnf_value *temp_val;

	if (DP_FAILED(rte_hash_lookup_data(vnf_handle_tbl, ul_addr6, (void **)&temp_val)))
		return NULL;

	return temp_val;
}

int dp_del_vnf_with_addr(const uint8_t ul_addr6[DP_VNF_IPV6_ADDR_SIZE])
{
	struct dp_vnf_value *temp_val;
	int ret;

	ret = rte_hash_lookup_data(vnf_handle_tbl, ul_addr6, (void **)&temp_val);
	if (DP_FAILED(ret)) {
		DPGRPC_LOG_WARNING("Cannot lookup VNF to delete", DP_LOG_IPV6(ul_addr6), DP_LOG_RET(ret));
		return ret;
	}

	rte_free(temp_val);

	ret = rte_hash_del_key(vnf_handle_tbl, ul_addr6);
	if (DP_FAILED(ret)) {
		DPGRPC_LOG_WARNING("Cannot remove VNF", DP_LOG_IPV6(ul_addr6), DP_LOG_RET(ret));
		return ret;
	}

	return DP_OK;
}

static __rte_always_inline bool dp_vnf_equal(const struct dp_vnf_value *val1, const struct dp_vnf_value *val2)
{
	return ((val1->portid == DP_VNF_MATCH_ALL_PORT_ID_VALUE) || (val1->portid == val2->portid))
		&& val1->alias_pfx.ip == val2->alias_pfx.ip
		&& val1->alias_pfx.length == val2->alias_pfx.length
		&& val1->v_type == val2->v_type;
}

int dp_find_vnf_with_value(const struct dp_vnf_value *val)
{
	struct dp_vnf_value *temp_val = NULL;
	uint32_t iter = 0;
	int32_t ret;
	const void *key;

	while ((ret = rte_hash_iterate(vnf_handle_tbl, &key, (void **)&temp_val, &iter)) != -ENOENT) {
		if (DP_FAILED(ret))
			return DP_GRPC_ERR_ITERATOR;

		if (dp_vnf_equal(val, temp_val))
			return DP_GRPC_OK;
	}
	return DP_GRPC_ERR_NOT_FOUND;
}

int dp_del_vnf_with_value(const struct dp_vnf_value *val)
{
	struct dp_vnf_value *temp_val = NULL;
	uint32_t iter = 0;
	int32_t ret;
	const void *key;
	int delete_count = 0;

	while ((ret = rte_hash_iterate(vnf_handle_tbl, &key, (void **)&temp_val, &iter)) != -ENOENT) {
		if (DP_FAILED(ret))
			return DP_GRPC_ERR_ITERATOR;

		if (dp_vnf_equal(val, temp_val)) {
			delete_count++;
			rte_free(temp_val);
			// this seems unsafe (deletion during traversal), but should be convered by having the table big enough
			// (ensured by dp_create_jhash_table())
			// should only ever fail on no-entry or invalid-arguments, but both are covered by rte_hash_iterate()
			ret = rte_hash_del_key(vnf_handle_tbl, key);
			if (DP_FAILED(ret))
				DPS_LOG_ERR("Cannot delete VNF key", DP_LOG_RET(ret));
		}
	}
	return delete_count > 0 ? DP_GRPC_OK : DP_GRPC_ERR_NOT_FOUND;
}

int dp_list_vnf_alias_routes(uint16_t port_id, enum vnf_type v_type, struct dp_grpc_responder *responder)
{
	const uint8_t *ul_addr6;
	struct dp_vnf_value *data;
	uint32_t iter = 0;
	struct dpgrpc_route *reply;
	int32_t ret;

	if (rte_hash_count(vnf_handle_tbl) == 0)
		return DP_GRPC_OK;

	dp_grpc_set_multireply(responder, sizeof(*reply));

	while ((ret = rte_hash_iterate(vnf_handle_tbl, (const void **)&ul_addr6, (void **)&data, &iter)) != -ENOENT) {
		if (DP_FAILED(ret)) {
			DPS_LOG_ERR("Cannot iterate VNF table", DP_LOG_RET(ret));
			return DP_GRPC_ERR_ITERATOR;
		}

		if (port_id != data->portid || data->v_type != v_type)
			continue;

		reply = dp_grpc_add_reply(responder);
		if (!reply)
			return DP_GRPC_ERR_OUT_OF_MEMORY;

		reply->pfx_addr.ip_type = RTE_ETHER_TYPE_IPV4;
		reply->pfx_addr.ipv4 = data->alias_pfx.ip;
		reply->pfx_length = data->alias_pfx.length;
		static_assert(sizeof(reply->trgt_addr.ipv6) == DP_VNF_IPV6_ADDR_SIZE,
					  "Invalid size of VNF hash table key");
		rte_memcpy(reply->trgt_addr.ipv6, ul_addr6, sizeof(reply->trgt_addr.ipv6));
	}

	return DP_GRPC_OK;
}
