// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#include "dp_vnf.h"
#include <rte_malloc.h>
#include "dp_error.h"
#include "dp_log.h"
#include "dp_lpm.h"
#include "grpc/dp_grpc_responder.h"

#define DP_VNF_MAX_TABLE_SIZE 1000

#define DP_LOG_VNF_WARNING(MESSAGE, VNF) \
		if ((VNF)->alias_pfx.ol.ip_type == RTE_ETHER_TYPE_IPV4) {\
			DPS_LOG_WARNING(MESSAGE, DP_LOG_VNF_TYPE((VNF)->type), DP_LOG_VNI((VNF)->vni), \
							DP_LOG_PORTID((VNF)->port_id), DP_LOG_IPV4((VNF)->alias_pfx.ol.ipv4), DP_LOG_PREFLEN((VNF)->alias_pfx.length)); } \
		else {\
			DPS_LOG_WARNING(MESSAGE, DP_LOG_VNF_TYPE((VNF)->type), DP_LOG_VNI((VNF)->vni), \
							DP_LOG_PORTID((VNF)->port_id), DP_LOG_IPV6((VNF)->alias_pfx.ol.ipv6), DP_LOG_PREFLEN((VNF)->alias_pfx.length)); } \

static struct rte_hash *vnf_handle_tbl = NULL;
static struct rte_hash *vnf_value_tbl = NULL;

int dp_vnf_init(int socket_id)
{
	vnf_handle_tbl = dp_create_jhash_table(DP_VNF_MAX_TABLE_SIZE, DP_VNF_IPV6_ADDR_SIZE,
										     "vnf_handle_table", socket_id);
	if (!vnf_handle_tbl)
		return DP_ERROR;

	vnf_value_tbl = dp_create_jhash_table(DP_VNF_MAX_TABLE_SIZE, sizeof(struct dp_vnf),
										  "vnf_value_table", socket_id);
	if (!vnf_value_tbl) {
		dp_free_jhash_table(vnf_handle_tbl); // rollback
		return DP_ERROR;
	}

	return DP_OK;
}

void dp_vnf_free(void)
{
	dp_free_jhash_table(vnf_handle_tbl);
}

static __rte_always_inline
void dp_fill_vnf_data(struct dp_vnf *vnf, enum dp_vnf_type type, uint16_t port_id, uint32_t vni,
						const struct dp_ip_address *src, uint8_t prefix_len)
{
	memset(vnf, 0, sizeof(*vnf)); // set all bits to 0, including possible padding bits

	vnf->type = type;
	vnf->port_id = port_id;
	vnf->vni = vni;
	vnf->alias_pfx.length = prefix_len;
	if (src->ip_type == RTE_ETHER_TYPE_IPV4) {
		vnf->alias_pfx.ol.ip_type = src->ip_type;
		vnf->alias_pfx.ol.ipv4 = src->ipv4;
	} else
		vnf->alias_pfx.ol = *src;
}

static int dp_add_vnf_value(const struct dp_vnf *vnf, const uint8_t ul_addr6[DP_VNF_IPV6_ADDR_SIZE])
{
	int ret;
	uint8_t *vnf_ul_addr6;

	DPS_LOG_INFO("Value to be used", _DP_LOG_PTR("ptr", ul_addr6), DP_LOG_IPV6(ul_addr6));

	vnf_ul_addr6 = rte_zmalloc("vnf_value_mapping", (size_t)DP_VNF_IPV6_ADDR_SIZE, RTE_CACHE_LINE_SIZE);
	if (!vnf_ul_addr6) {
		DPS_LOG_WARNING("VNF value allocation failed", DP_LOG_IPV6(ul_addr6));
		return DP_ERROR;
	}

	assert(!memcmp(ul_addr6, dp_conf_get_underlay_ip(), 8));
	memcpy(vnf_ul_addr6, ul_addr6, DP_IPV6_ADDR_SIZE);

	assert(!memcmp(vnf_ul_addr6, ul_addr6, DP_IPV6_ADDR_SIZE));
	assert(!memcmp(vnf_ul_addr6, dp_conf_get_underlay_ip(), 8));

	DPS_LOG_INFO("Value sending to table", _DP_LOG_PTR("ptr", vnf_ul_addr6), DP_LOG_IPV6(vnf_ul_addr6));
	ret = rte_hash_add_key_data(vnf_value_tbl, vnf, vnf_ul_addr6);
	if (DP_FAILED(ret)) {
		DPS_LOG_ERR("Cannot add VNF value and the corresponding underlying IPv6 address to table", DP_LOG_RET(ret));
		rte_free(vnf_ul_addr6);
		return DP_ERROR;
	}

	assert(!memcmp(vnf_ul_addr6, ul_addr6, DP_IPV6_ADDR_SIZE));
	assert(!memcmp(vnf_ul_addr6, dp_conf_get_underlay_ip(), 8));

	uint8_t *stored_vnf_ul_addr6;

	ret = rte_hash_lookup_data(vnf_value_tbl, vnf, (void **)&stored_vnf_ul_addr6);
	assert(!DP_FAILED(ret));
	DPS_LOG_INFO("Value stored in table", _DP_LOG_PTR("ptr", stored_vnf_ul_addr6), DP_LOG_IPV6(stored_vnf_ul_addr6));
	assert(stored_vnf_ul_addr6 == vnf_ul_addr6);
	assert(!memcmp(vnf_ul_addr6, stored_vnf_ul_addr6, DP_IPV6_ADDR_SIZE));
	assert(!memcmp(stored_vnf_ul_addr6, dp_conf_get_underlay_ip(), 8));

	return DP_OK;
}

static int dp_delete_vnf_value(struct dp_vnf *vnf)
{
	int ret;
	uint8_t *ul_addr6 = NULL;


	ret = rte_hash_lookup_data(vnf_value_tbl, vnf, (void **)&ul_addr6);
	if (DP_FAILED(ret)) {
		DP_LOG_VNF_WARNING("VNF value lookup failed", vnf)
		return DP_ERROR;
	}

	ret = rte_hash_del_key(vnf_value_tbl, vnf);
	if (DP_FAILED(ret)) {
		DPGRPC_LOG_WARNING("Cannot remove VNF for a underlying IPv6 address", DP_LOG_IPV6(ul_addr6), DP_LOG_RET(ret));
		return ret;
	}

	rte_free(ul_addr6);
	return DP_OK;
}

static bool dp_vnf_value_exists(const struct dp_vnf *vnf)
{
	int ret;

	ret = rte_hash_lookup(vnf_value_tbl, vnf);
	if (DP_FAILED(ret)) {
		if (ret != -ENOENT)
			DPS_LOG_ERR("Cannot lookup VNF value in table", DP_LOG_RET(ret));
		return false;
	}

	return true;
}

int dp_add_vnf(const uint8_t ul_addr6[DP_VNF_IPV6_ADDR_SIZE], enum dp_vnf_type type,
			   uint16_t port_id, uint32_t vni, struct dp_ip_address *prefix, uint8_t prefix_len)
{
	struct dp_vnf *vnf;
	int ret;

	if (rte_hash_lookup(vnf_handle_tbl, ul_addr6) != -ENOENT)
		return DP_ERROR;

	vnf = rte_zmalloc("vnf_handle_mapping", sizeof(struct dp_vnf), RTE_CACHE_LINE_SIZE);
	if (!vnf) {
		if (prefix->ip_type == RTE_ETHER_TYPE_IPV4)
			DPS_LOG_WARNING("VNF handle allocation failed", DP_LOG_VNF_TYPE(type), DP_LOG_VNI(vni),
							DP_LOG_PORTID(port_id), DP_LOG_IPV4(prefix->ipv4), DP_LOG_PREFLEN(prefix_len));
		else
			DPS_LOG_WARNING("VNF handle allocation failed", DP_LOG_VNF_TYPE(type), DP_LOG_VNI(vni),
							DP_LOG_PORTID(port_id), DP_LOG_IPV6(prefix->ipv6), DP_LOG_PREFLEN(prefix_len));
		return DP_ERROR;
	}

	dp_fill_vnf_data(vnf, type, port_id, vni, prefix, prefix_len);

	ret = rte_hash_add_key_data(vnf_handle_tbl, ul_addr6, vnf);
	if (DP_FAILED(ret)) {
		DP_LOG_VNF_WARNING("VNF handle addition failed", vnf)
		rte_free(vnf);
		return DP_ERROR;
	}

	if (DP_FAILED(dp_add_vnf_value(vnf, ul_addr6))) {
		DP_LOG_VNF_WARNING("Adding VNF value failed", vnf)
		dp_del_vnf(ul_addr6); //rollback
		return DP_ERROR;
	}

	return DP_OK;
}

const struct dp_vnf *dp_get_vnf(const uint8_t ul_addr6[DP_VNF_IPV6_ADDR_SIZE])
{
	struct dp_vnf *vnf;

	if (DP_FAILED(rte_hash_lookup_data(vnf_handle_tbl, ul_addr6, (void **)&vnf)))
		return NULL;

	return vnf;
}

int dp_del_vnf(const uint8_t ul_addr6[DP_VNF_IPV6_ADDR_SIZE])
{
	struct dp_vnf *vnf;
	int ret;

	ret = rte_hash_lookup_data(vnf_handle_tbl, ul_addr6, (void **)&vnf);
	if (DP_FAILED(ret)) {
		DPGRPC_LOG_WARNING("Cannot lookup VNF to delete", DP_LOG_IPV6(ul_addr6), DP_LOG_RET(ret));
		return ret;
	}

	ret = rte_hash_del_key(vnf_handle_tbl, ul_addr6);
	if (DP_FAILED(ret)) {
		DPGRPC_LOG_WARNING("Cannot remove VNF", DP_LOG_IPV6(ul_addr6), DP_LOG_RET(ret));
		return ret;
	}

	ret = dp_delete_vnf_value(vnf);
	if (DP_FAILED(ret)) {
		DPGRPC_LOG_WARNING("Cannot delete VNF value record");
		rte_free(vnf);
		return ret;
	}

	rte_free(vnf);

	return DP_OK;
}

bool dp_vnf_lbprefix_exists(uint16_t port_id, uint32_t vni, struct dp_ip_address *prefix_ip, uint8_t prefix_len)
{
	struct dp_vnf vnf;

	dp_fill_vnf_data(&vnf, DP_VNF_TYPE_LB_ALIAS_PFX, port_id, vni, prefix_ip, prefix_len);

	return dp_vnf_value_exists(&vnf);
}

int dp_del_vnf_by_value(enum dp_vnf_type type, uint16_t port_id, uint32_t vni, struct dp_ip_address *prefix_ip, uint8_t prefix_len)
{
	uint8_t *vnf_ul_addr6;
	int32_t ret;
	struct dp_vnf target_vnf;

	dp_fill_vnf_data(&target_vnf, type, port_id, vni, prefix_ip, prefix_len);

	ret = rte_hash_lookup_data(vnf_value_tbl, &target_vnf, (void **)&vnf_ul_addr6);
	if (DP_FAILED(ret)) {
		if (ret == -ENOENT)
			return DP_GRPC_ERR_NOT_FOUND;
		DP_LOG_VNF_WARNING("VNF value key lookup failed due to invalid parameters", &target_vnf)
		return DP_GRPC_ERR_VNF_DELETE;
	}

	DPS_LOG_INFO("Value found in table", _DP_LOG_PTR("ptr", vnf_ul_addr6), DP_LOG_IPV6(vnf_ul_addr6));
	assert(!memcmp(vnf_ul_addr6, dp_conf_get_underlay_ip(), 8));

	ret = dp_del_vnf(vnf_ul_addr6);
	if (DP_FAILED(ret)) {
		if (ret == -ENOENT)
			return DP_GRPC_ERR_NOT_FOUND;
		DP_LOG_VNF_WARNING("VNF underlying IPv6 as key lookup failed due to invalid parameters", &target_vnf)
		return DP_GRPC_ERR_VNF_DELETE;
	}

	return DP_OK;
}

int dp_list_vnf_alias_prefixes(uint16_t port_id, enum dp_vnf_type type, struct dp_grpc_responder *responder)
{
	const uint8_t *ul_addr6;
	struct dp_vnf *vnf;
	uint32_t iter = 0;
	struct dpgrpc_route *reply;
	int32_t ret;

	if (rte_hash_count(vnf_handle_tbl) == 0)
		return DP_GRPC_OK;

	dp_grpc_set_multireply(responder, sizeof(*reply));

	while ((ret = rte_hash_iterate(vnf_handle_tbl, (const void **)&ul_addr6, (void **)&vnf, &iter)) != -ENOENT) {
		if (DP_FAILED(ret)) {
			DPS_LOG_ERR("Cannot iterate VNF table", DP_LOG_RET(ret));
			return DP_GRPC_ERR_ITERATOR;
		}

		if (port_id != vnf->port_id || vnf->type != type)
			continue;

		reply = dp_grpc_add_reply(responder);
		if (!reply)
			return DP_GRPC_ERR_OUT_OF_MEMORY;

		reply->pfx_addr = vnf->alias_pfx.ol;
		reply->pfx_length = vnf->alias_pfx.length;
		static_assert(sizeof(reply->trgt_addr.ipv6) == DP_VNF_IPV6_ADDR_SIZE,
					  "Invalid size of VNF hash table key");
		rte_memcpy(reply->trgt_addr.ipv6, ul_addr6, sizeof(reply->trgt_addr.ipv6));
	}

	return DP_GRPC_OK;
}
