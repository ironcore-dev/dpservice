// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#include "dp_vnf.h"
#include <rte_malloc.h>
#include "dp_error.h"
#include "dp_log.h"
#include "dp_lpm.h"
#include "grpc/dp_grpc_responder.h"

#define DP_VNF_MAX_TABLE_SIZE 1000

#define DPS_LOG_VNF_WARNING(MESSAGE, VNF) \
	dp_vnf_log_warning(MESSAGE, (VNF)->type, (VNF)->vni, (VNF)->port_id, &(VNF)->alias_pfx.ol, (VNF)->alias_pfx.length)

static struct rte_hash *vnf_handle_tbl = NULL;
static struct rte_hash *vnf_value_tbl = NULL;

int dp_vnf_init(int socket_id)
{
	vnf_handle_tbl = dp_create_jhash_table(DP_VNF_MAX_TABLE_SIZE, sizeof(union dp_ipv6),
										   DP_VNF_TABLE_NAME, socket_id);
	if (!vnf_handle_tbl)
		return DP_ERROR;

	vnf_value_tbl = dp_create_jhash_table(DP_VNF_MAX_TABLE_SIZE, sizeof(struct dp_vnf),
										  DP_VNF_REVERSE_TABLE_NAME, socket_id);
	if (!vnf_value_tbl) {
		dp_free_jhash_table(vnf_handle_tbl);
		return DP_ERROR;
	}

	return DP_OK;
}

void dp_vnf_free(void)
{
	dp_free_jhash_table(vnf_handle_tbl);
}

static inline void dp_vnf_log_warning(const char *message,
									  enum dp_vnf_type type, uint32_t vni, uint16_t port_id,
									  const struct dp_ip_address *prefix, uint8_t length)
{
	if (prefix->is_v6)
		DPS_LOG_WARNING(message, DP_LOG_VNF_TYPE(type), DP_LOG_VNI(vni),
						DP_LOG_PORTID(port_id), DP_LOG_IPV6(prefix->ipv6), DP_LOG_PREFLEN(length));
	else
		DPS_LOG_WARNING(message, DP_LOG_VNF_TYPE(type), DP_LOG_VNI(vni),
						DP_LOG_PORTID(port_id), DP_LOG_IPV4(prefix->ipv4), DP_LOG_PREFLEN(length));
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
	dp_copy_ipaddr(&vnf->alias_pfx.ol, src);
}

static int dp_add_vnf_value(const struct dp_vnf *vnf, const union dp_ipv6 *ul_addr6)
{
	int ret;
	union dp_ipv6 *vnf_ul_addr6;

	vnf_ul_addr6 = rte_malloc("vnf_value_mapping", sizeof(*vnf_ul_addr6), RTE_CACHE_LINE_SIZE);
	if (!vnf_ul_addr6) {
		DPS_LOG_WARNING("VNF value allocation failed", DP_LOG_IPV6(*ul_addr6));
		return DP_ERROR;
	}

	dp_copy_ipv6(vnf_ul_addr6, ul_addr6);

	ret = rte_hash_add_key_data(vnf_value_tbl, vnf, vnf_ul_addr6);
	if (DP_FAILED(ret)) {
		DPS_LOG_ERR("Cannot add VNF value and the corresponding underlying IPv6 address to table", DP_LOG_IPV6(*vnf_ul_addr6), DP_LOG_RET(ret));
		rte_free(vnf_ul_addr6);
		return DP_ERROR;
	}

	return DP_OK;
}

static int dp_delete_vnf_value(const struct dp_vnf *vnf)
{
	hash_sig_t hash = rte_hash_hash(vnf_value_tbl, vnf);
	union dp_ipv6 *ul_addr6;
	int ret;

	ret = rte_hash_lookup_with_hash_data(vnf_value_tbl, vnf, hash, (void **)&ul_addr6);
	if (DP_FAILED(ret)) {
		DPS_LOG_VNF_WARNING("VNF value lookup failed", vnf);
		return DP_ERROR;
	}

	ret = rte_hash_del_key_with_hash(vnf_value_tbl, vnf, hash);
	if (DP_FAILED(ret)) {
		DPS_LOG_WARNING("Cannot remove VNF for a underlying IPv6 address", DP_LOG_IPV6(*ul_addr6), DP_LOG_RET(ret));
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

int dp_add_vnf(const union dp_ipv6 *ul_addr6, enum dp_vnf_type type,
			   uint16_t port_id, uint32_t vni, const struct dp_ip_address *prefix, uint8_t prefix_len)
{
	hash_sig_t hash = rte_hash_hash(vnf_handle_tbl, ul_addr6);
	struct dp_vnf *vnf;
	int ret;

	ret = rte_hash_lookup_with_hash(vnf_handle_tbl, ul_addr6, hash);
	if (DP_SUCCESS(ret)) {
		DPS_LOG_WARNING("Underlay address already registered", DP_LOG_IPV6(*ul_addr6));
		return DP_ERROR;
	} else if (ret != -ENOENT) {
		DPS_LOG_ERR("VNF hash table lookup failed", DP_LOG_RET(ret));
		return DP_ERROR;
	}

	vnf = rte_malloc("vnf_handle_mapping", sizeof(struct dp_vnf), RTE_CACHE_LINE_SIZE);
	if (!vnf) {
		dp_vnf_log_warning("VNF handle allocation failed", type, vni, port_id, prefix, prefix_len);
		return DP_ERROR;
	}

	dp_fill_vnf_data(vnf, type, port_id, vni, prefix, prefix_len);

	ret = rte_hash_add_key_with_hash_data(vnf_handle_tbl, ul_addr6, hash, vnf);
	if (DP_FAILED(ret)) {
		DPS_LOG_VNF_WARNING("VNF handle addition failed", vnf);
		rte_free(vnf);
		return DP_ERROR;
	}

	if (DP_FAILED(dp_add_vnf_value(vnf, ul_addr6))) {
		DPS_LOG_VNF_WARNING("Adding VNF value failed", vnf);
		dp_del_vnf(ul_addr6);
		return DP_ERROR;
	}

	return DP_OK;
}

const struct dp_vnf *dp_get_vnf(const union dp_ipv6 *ul_addr6)
{
	struct dp_vnf *vnf;

	if (DP_FAILED(rte_hash_lookup_data(vnf_handle_tbl, ul_addr6, (void **)&vnf)))
		return NULL;

	return vnf;
}

int dp_del_vnf(const union dp_ipv6 *ul_addr6)
{
	hash_sig_t hash = rte_hash_hash(vnf_handle_tbl, ul_addr6);
	struct dp_vnf *vnf;
	int ret;

	ret = rte_hash_lookup_with_hash_data(vnf_handle_tbl, ul_addr6, hash, (void **)&vnf);
	if (DP_FAILED(ret)) {
		DPS_LOG_WARNING("Cannot lookup VNF to delete", DP_LOG_IPV6(*ul_addr6), DP_LOG_RET(ret));
		return ret;
	}

	ret = rte_hash_del_key_with_hash(vnf_handle_tbl, ul_addr6, hash);
	if (DP_FAILED(ret)) {
		DPS_LOG_WARNING("Cannot remove VNF", DP_LOG_IPV6(*ul_addr6), DP_LOG_RET(ret));
		return ret;
	}

	ret = dp_delete_vnf_value(vnf);
	if (DP_FAILED(ret)) {
		DPS_LOG_WARNING("Cannot delete VNF value record");
		rte_free(vnf);
		return ret;
	}

	rte_free(vnf);

	return DP_OK;
}

bool dp_vnf_lbprefix_exists(uint16_t port_id, uint32_t vni, const struct dp_ip_address *prefix_ip, uint8_t prefix_len)
{
	struct dp_vnf vnf;

	dp_fill_vnf_data(&vnf, DP_VNF_TYPE_LB_ALIAS_PFX, port_id, vni, prefix_ip, prefix_len);

	return dp_vnf_value_exists(&vnf);
}

int dp_del_vnf_by_value(enum dp_vnf_type type, uint16_t port_id, uint32_t vni, const struct dp_ip_address *prefix_ip, uint8_t prefix_len)
{
	struct dp_vnf target_vnf;
	union dp_ipv6 *vnf_ul_addr6;
	int32_t ret;

	dp_fill_vnf_data(&target_vnf, type, port_id, vni, prefix_ip, prefix_len);

	ret = rte_hash_lookup_data(vnf_value_tbl, &target_vnf, (void **)&vnf_ul_addr6);
	if (DP_FAILED(ret)) {
		if (ret == -ENOENT)
			return DP_GRPC_ERR_NOT_FOUND;
		DPS_LOG_VNF_WARNING("VNF value key lookup failed due to invalid parameters", &target_vnf);
		return DP_GRPC_ERR_VNF_DELETE;
	}

	// This actually does the lookup again, but as this function is rarely called (orchestration only), it does nto matter
	ret = dp_del_vnf(vnf_ul_addr6);
	if (DP_FAILED(ret)) {
		if (ret == -ENOENT)
			return DP_GRPC_ERR_NOT_FOUND;
		DPS_LOG_VNF_WARNING("VNF underlying IPv6 as key lookup failed due to invalid parameters", &target_vnf);
		return DP_GRPC_ERR_VNF_DELETE;
	}

	return DP_OK;
}

int dp_list_vnf_alias_prefixes(uint16_t port_id, enum dp_vnf_type type, struct dp_grpc_responder *responder)
{
	const union dp_ipv6 *ul_addr6;
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

		dp_copy_ipaddr(&reply->pfx_addr, &vnf->alias_pfx.ol);
		reply->pfx_length = vnf->alias_pfx.length;
		dp_set_ipaddr6(&reply->trgt_addr, ul_addr6);
	}

	return DP_GRPC_OK;
}
