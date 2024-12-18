// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#include "dp_lb.h"
#include <stdlib.h>
#include <time.h>
#include <rte_common.h>
#include <rte_errno.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_malloc.h>
#include <rte_rib6.h>
#include "dp_error.h"
#include "dp_flow.h"
#include "dp_log.h"
#include "dp_maglev.h"
#include "grpc/dp_grpc_responder.h"

static struct rte_hash *lb_table = NULL;
static struct rte_hash *id_map_lb_tbl = NULL;

int dp_lb_init(int socket_id)
{
	lb_table = dp_create_jhash_table(DP_LB_TABLE_MAX, sizeof(struct lb_key),
									 DP_LB_TABLE_NAME, socket_id);
	if (!lb_table)
		return DP_ERROR;

	id_map_lb_tbl = dp_create_jhash_table(DP_LB_TABLE_MAX, DP_LB_ID_MAX_LEN,
										  DP_LB_ID_TABLE_NAME, socket_id);
	if (!id_map_lb_tbl)
		return DP_ERROR;

	return DP_OK;
}

void dp_lb_free(void)
{
	dp_free_jhash_table(id_map_lb_tbl);
	dp_free_jhash_table(lb_table);
}

static int dp_map_lb_handle(const void *id_key, const struct lb_key *l_key, struct lb_value *l_val)
{
	struct lb_key *lb_k;
	int ret;

	lb_k = rte_malloc("lb_id_mapping", sizeof(struct lb_key), RTE_CACHE_LINE_SIZE);
	if (!lb_k) {
		DPS_LOG_ERR("Cannot allocate LB id mapping data");
		return DP_ERROR;
	}

	rte_memcpy(l_val->lb_id, id_key, sizeof(l_val->lb_id));
	rte_memcpy(lb_k, l_key, sizeof(*lb_k));
	ret = rte_hash_add_key_data(id_map_lb_tbl, id_key, lb_k);
	if (DP_FAILED(ret)) {
		DPS_LOG_ERR("Cannot insert LB id mapping data", DP_LOG_RET(ret));
		rte_free(lb_k);
		return ret;
	}

	return DP_OK;
}

int dp_create_lb(struct dpgrpc_lb *lb, const union dp_ipv6 *ul_ip)
{
	struct lb_value *lb_val;
	struct lb_key lb_key;

	lb_key.vni = lb->vni;
	dp_copy_ipaddr(&lb_key.ip, &lb->addr);

	if (!DP_FAILED(rte_hash_lookup(lb_table, &lb_key)))
		return DP_GRPC_ERR_ALREADY_EXISTS;

	lb_val = rte_zmalloc("lb_val", sizeof(struct lb_value), RTE_CACHE_LINE_SIZE);
	if (!lb_val)
		goto err;

	if (DP_FAILED(rte_hash_add_key_data(lb_table, &lb_key, lb_val)))
		goto err_free;

	if (DP_FAILED(dp_map_lb_handle(lb->lb_id, &lb_key, lb_val)))
		goto err_free;

	dp_copy_ipv6(&lb_val->lb_ul_addr, ul_ip);
	for (int i = 0; i < DP_LB_MAX_PORTS; ++i) {
		lb_val->ports[i].port = htons(lb->lbports[i].port);
		lb_val->ports[i].protocol = lb->lbports[i].protocol;
	}
	return DP_GRPC_OK;

err_free:
	rte_free(lb_val);
err:
	return DP_GRPC_ERR_OUT_OF_MEMORY;
}

int dp_get_lb(const void *id_key, struct dpgrpc_lb *out_lb)
{
	struct lb_value *lb_val = NULL;
	struct lb_key *lb_k;
	int32_t i;

	if (DP_FAILED(rte_hash_lookup_data(id_map_lb_tbl, id_key, (void **)&lb_k)))
		return DP_GRPC_ERR_NOT_FOUND;

	if (DP_FAILED(rte_hash_lookup_data(lb_table, lb_k, (void **)&lb_val)))
		return DP_GRPC_ERR_NO_BACKIP;

	out_lb->vni = lb_k->vni;
	dp_copy_ipaddr(&out_lb->addr, &lb_k->ip);
	dp_copy_ipv6(&out_lb->ul_addr6, &lb_val->lb_ul_addr);

	for (i = 0; i < DP_LB_MAX_PORTS; i++) {
		out_lb->lbports[i].port = ntohs(lb_val->ports[i].port);
		out_lb->lbports[i].protocol = lb_val->ports[i].protocol;
	}

	return DP_GRPC_OK;
}

int dp_delete_lb(const void *id_key)
{
	struct lb_value *lb_val = NULL;
	struct lb_key *lb_k;
	int ret;

	if (DP_FAILED(rte_hash_lookup_data(id_map_lb_tbl, id_key, (void **)&lb_k)))
		return DP_GRPC_ERR_NOT_FOUND;

	ret = rte_hash_lookup_data(lb_table, lb_k, (void **)&lb_val);
	if (DP_FAILED(ret)) {
		DPS_LOG_WARNING("Cannot get LB backing IP", DP_LOG_RET(ret));
	} else {
		rte_free(lb_val);
		ret = rte_hash_del_key(lb_table, lb_k);
		if (DP_FAILED(ret))
			DPS_LOG_WARNING("Cannot delete LB key", DP_LOG_RET(ret));
	}

	rte_free(lb_k);
	ret = rte_hash_del_key(id_map_lb_tbl, id_key);
	if (DP_FAILED(ret))
		DPS_LOG_WARNING("Cannot delete LB map key", DP_LOG_RET(ret));

	return DP_GRPC_OK;
}

int dp_list_lbs(struct dp_grpc_responder *responder)
{
	struct dpgrpc_lb *reply;
	uint32_t iter = 0;
	const struct lb_key *lb_key;
	struct lb_value *lb_val;
	int ret;

	if (rte_hash_count(id_map_lb_tbl) == 0)
		return DP_GRPC_OK;

	dp_grpc_set_multireply(responder, sizeof(*reply));

	while ((ret = rte_hash_iterate(lb_table, (const void **)&lb_key, (void **)&lb_val, &iter)) != -ENOENT) {
		if (DP_FAILED(ret))
			return DP_GRPC_ERR_ITERATOR;

		reply = dp_grpc_add_reply(responder);
		if (!reply)
			return DP_GRPC_ERR_OUT_OF_MEMORY;

		static_assert(sizeof(reply->lb_id) == sizeof(lb_val->lb_id), "Incompatible Loadbalancer ID fields");
		memcpy(reply->lb_id, lb_val->lb_id, sizeof(reply->lb_id));

		reply->vni = lb_key->vni;
		dp_copy_ipaddr(&reply->addr, &lb_key->ip);
		dp_copy_ipv6(&reply->ul_addr6, &lb_val->lb_ul_addr);

		for (int i = 0; i < DP_LB_MAX_PORTS; ++i) {
			reply->lbports[i].port = ntohs(lb_val->ports[i].port);
			reply->lbports[i].protocol = lb_val->ports[i].protocol;
		}
	}

	return DP_GRPC_OK;
}

bool dp_is_lb_enabled(void)
{
	return rte_hash_count(lb_table) > 0;
}

bool dp_is_ip_lb(struct dp_flow *df, uint32_t vni)
{
	struct lb_key lb_key;

	lb_key.vni = vni;

	if (df->l3_type == RTE_ETHER_TYPE_IPV4)
		dp_set_ipaddr4(&lb_key.ip, ntohl(df->dst.dst_addr));
	else if (df->l3_type == RTE_ETHER_TYPE_IPV6)
		dp_set_ipaddr6(&lb_key.ip, &df->dst.dst_addr6);
	else
		return false;

	return !DP_FAILED(rte_hash_lookup(lb_table, &lb_key));
}

static bool dp_lb_is_back_ip_inserted(struct lb_value *val, const union dp_ipv6 *b_ip)
{
	for (int i = 0; i < DP_LB_MAX_IPS_PER_VIP; ++i)
		if (dp_ipv6_match(&val->back_end_ips[i], b_ip))
			return true;
	return false;
}

static __rte_always_inline bool dp_lb_port_match(struct lb_value *lb_val, uint16_t port_dst, uint8_t proto)
{
	for (struct lb_port *port = lb_val->ports;
			port < lb_val->ports + DP_LB_MAX_PORTS && port->port != 0;
			++port)
		if (port->port == port_dst && port->protocol == proto)
			return true;
	return false;
}

const union dp_ipv6 *dp_lb_get_backend_ip(struct flow_key *flow_key, uint32_t vni)
{
	struct lb_value *lb_val = NULL;
	struct lb_key lb_key;

	lb_key.vni = vni;
	dp_copy_ipaddr(&lb_key.ip, &flow_key->l3_dst);

	if (rte_hash_lookup_data(lb_table, &lb_key, (void **)&lb_val) < 0)
		return NULL;

	if (lb_val->back_end_cnt == 0)
		return NULL;

	if (!dp_lb_port_match(lb_val, htons(flow_key->port_dst), flow_key->proto))
		return NULL;

	int pos = lb_val->maglev_hash[dp_get_conntrack_flow_hash_value(flow_key) % DP_LB_MAGLEV_LOOKUP_SIZE];

	return &lb_val->back_end_ips[pos];
}

int dp_get_lb_back_ips(const void *id_key, struct dp_grpc_responder *responder)
{
	struct lb_key *lb_k;
	struct lb_value *lb_val;
	struct dpgrpc_lb_target *reply;

	if (DP_FAILED(rte_hash_lookup_data(id_map_lb_tbl, id_key, (void **)&lb_k)))
		return DP_GRPC_ERR_NO_LB;

	if (DP_FAILED(rte_hash_lookup_data(lb_table, lb_k, (void **)&lb_val)))
		return DP_GRPC_ERR_NO_BACKIP;

	dp_grpc_set_multireply(responder, sizeof(*reply));

	for (int i = 0; i < DP_LB_MAX_IPS_PER_VIP; ++i) {
		if (!dp_is_ipv6_zero(&lb_val->back_end_ips[i])) {
			reply = dp_grpc_add_reply(responder);
			if (!reply)
				return DP_GRPC_ERR_OUT_OF_MEMORY;
			dp_set_ipaddr6(&reply->addr, &lb_val->back_end_ips[i]);
		}
	}

	return DP_GRPC_OK;
}

int dp_add_lb_back_ip(const void *id_key, const union dp_ipv6 *back_ip)
{
	struct lb_value *lb_val = NULL;
	struct lb_key *lb_k;

	if (DP_FAILED(rte_hash_lookup_data(id_map_lb_tbl, id_key, (void **)&lb_k)))
		return DP_GRPC_ERR_NO_LB;

	if (DP_FAILED(rte_hash_lookup_data(lb_table, lb_k, (void **)&lb_val)))
		return DP_GRPC_ERR_NO_BACKIP;

	if (dp_lb_is_back_ip_inserted(lb_val, back_ip))
		return DP_GRPC_ERR_ALREADY_EXISTS;

	if (DP_FAILED(dp_add_maglev_backend(lb_val, back_ip)))
		return DP_GRPC_ERR_BACKIP_ADD;

	return DP_GRPC_OK;
}

int dp_del_lb_back_ip(const void *id_key, const union dp_ipv6 *back_ip)
{
	struct lb_value *lb_val;
	struct lb_key *lb_k;

	if (DP_FAILED(rte_hash_lookup_data(id_map_lb_tbl, id_key, (void **)&lb_k)))
		return DP_GRPC_ERR_NO_LB;

	if (DP_FAILED(rte_hash_lookup_data(lb_table, lb_k, (void **)&lb_val)))
		return DP_GRPC_ERR_NO_BACKIP;

	return dp_delete_maglev_backend(lb_val, back_ip);
}
