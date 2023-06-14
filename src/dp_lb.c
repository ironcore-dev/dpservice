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
#include "grpc/dp_grpc_responder.h"

static struct rte_hash *ipv4_lb_tbl = NULL;
static struct rte_hash *id_map_lb_tbl = NULL;

int dp_lb_init(int socket_id)
{
	ipv4_lb_tbl = dp_create_jhash_table(DP_LB_TABLE_MAX, sizeof(struct lb_key),
										"ipv4_lb_table", socket_id);
	if (!ipv4_lb_tbl)
		return DP_ERROR;

	id_map_lb_tbl = dp_create_jhash_table(DP_LB_TABLE_MAX, DP_LB_ID_SIZE,
										  "lb_id_map_table", socket_id);
	if (!id_map_lb_tbl)
		return DP_ERROR;

	return DP_OK;
}

void dp_lb_free()
{
	dp_free_jhash_table(id_map_lb_tbl);
	dp_free_jhash_table(ipv4_lb_tbl);
}

static int dp_map_lb_handle(void *id_key, struct lb_key *l_key, struct lb_value *l_val)
{
	struct lb_key *lb_k;
	int ret;

	lb_k = rte_zmalloc("lb_id_mapping", sizeof(struct lb_key), RTE_CACHE_LINE_SIZE);
	if (!lb_k) {
		DPS_LOG_ERR("Cannot allocate LB id mapping data");
		return DP_ERROR;
	}

	rte_memcpy(l_val->lb_id, id_key, DP_LB_ID_SIZE);
	*lb_k = *l_key;
	ret = rte_hash_add_key_data(id_map_lb_tbl, id_key, lb_k);
	if (DP_FAILED(ret)) {
		DPS_LOG_ERR("Cannot insert LB id mapping data %s", dp_strerror(ret));
		rte_free(lb_k);
		return ret;
	}

	return DP_OK;
}

int dp_create_lb(dp_add_lb *add_lb, uint8_t *ul_ip)
{
	struct lb_value *lb_val = NULL;
	struct lb_key nkey = {
		.ip = ntohl(add_lb->vip.vip_addr),
		.vni = add_lb->vni
	};

	lb_val = rte_zmalloc("lb_val", sizeof(struct lb_value), RTE_CACHE_LINE_SIZE);
	if (!lb_val)
		goto err;

	if (DP_FAILED(rte_hash_add_key_data(ipv4_lb_tbl, &nkey, lb_val)))
		goto err_free;

	if (DP_FAILED(dp_map_lb_handle((void *)add_lb->lb_id, &nkey, lb_val)))
		goto err_free;

	rte_memcpy(lb_val->lb_ul_addr, ul_ip, DP_VNF_IPV6_ADDR_SIZE);
	for (int i = 0; i < DP_LB_PORT_SIZE; ++i) {
		lb_val->ports[i].port = ntohs(add_lb->lbports[i].port);
		lb_val->ports[i].protocol = add_lb->lbports[i].protocol;
	}
	return DP_GRPC_OK;

err_free:
	rte_free(lb_val);
err:
	return DP_GRPC_ERR_OUT_OF_MEMORY;
}

int dp_get_lb(void *id_key, dp_lb *list_lb)
{
	struct lb_value *lb_val = NULL;
	struct lb_key *lb_k;
	int32_t i;

	if (DP_FAILED(rte_hash_lookup_data(id_map_lb_tbl, id_key, (void **)&lb_k)))
		return DP_GRPC_ERR_NOT_FOUND;

	if (DP_FAILED(rte_hash_lookup_data(ipv4_lb_tbl, lb_k, (void **)&lb_val)))
		return DP_GRPC_ERR_NO_BACKIP;

	list_lb->ip_type = RTE_ETHER_TYPE_IPV4;
	list_lb->vni = lb_k->vni;
	list_lb->vip.vip_addr = htonl(lb_k->ip);
	rte_memcpy(list_lb->ul_addr6, lb_val->lb_ul_addr, DP_VNF_IPV6_ADDR_SIZE);

	for (i = 0; i < DP_LB_PORT_SIZE; i++) {
		list_lb->lbports[i].port = htons(lb_val->ports[i].port);
		list_lb->lbports[i].protocol = lb_val->ports[i].protocol;
	}

	return DP_GRPC_OK;
}

int dp_delete_lb(void *id_key)
{
	struct lb_value *lb_val = NULL;
	struct lb_key *lb_k;
	int ret;

	if (DP_FAILED(rte_hash_lookup_data(id_map_lb_tbl, id_key, (void **)&lb_k)))
		return DP_GRPC_ERR_NOT_FOUND;

	ret = rte_hash_lookup_data(ipv4_lb_tbl, lb_k, (void **)&lb_val);
	if (DP_FAILED(ret)) {
		DPS_LOG_WARNING("Cannot get LB backing IP %s", dp_strerror(ret));
	} else {
		rte_free(lb_val);
		ret = rte_hash_del_key(ipv4_lb_tbl, lb_k);
		if (DP_FAILED(ret))
			DPS_LOG_WARNING("Cannot delete LB key %s", dp_strerror(ret));
	}

	rte_free(lb_k);
	ret = rte_hash_del_key(id_map_lb_tbl, id_key);
	if (DP_FAILED(ret))
		DPS_LOG_WARNING("Cannot delete LB map key %s", dp_strerror(ret));

	return DP_GRPC_OK;
}

bool dp_is_lb_enabled()
{
	return (rte_hash_count(ipv4_lb_tbl) > 0);
}

bool dp_is_ip_lb(uint32_t vm_ip, uint32_t vni)
{
	struct lb_key nkey = {
		.ip = vm_ip,
		.vni = vni
	};

	return !DP_FAILED(rte_hash_lookup(ipv4_lb_tbl, &nkey));
}

static int dp_lb_last_free_pos(struct lb_value *val)
{
	int ret = -1, k;

	for (k = 0; k < DP_LB_MAX_IPS_PER_VIP; k++) {
		if (val->back_end_ips[k][0] == 0)
			break;
	}
	if (k != DP_LB_MAX_IPS_PER_VIP)
		ret = k;

	return ret;
}

static void dp_lb_delete_back_ip(struct lb_value *val, uint8_t *b_ip)
{
	for (int i = 0; i < DP_LB_MAX_IPS_PER_VIP; ++i) {
		if (rte_rib6_is_equal((uint8_t *)&val->back_end_ips[i][0], b_ip)) {
			memset(&val->back_end_ips[i][0], 0, 16);
			val->back_end_cnt--;
			break;
		}
	}
}

static bool dp_lb_is_back_ip_inserted(struct lb_value *val, uint8_t *b_ip)
{
	for (int i = 0; i < DP_LB_MAX_IPS_PER_VIP; ++i)
		if (rte_rib6_is_equal((uint8_t *)&val->back_end_ips[i][0], b_ip))
			return true;
	return false;
}

static int dp_lb_rr_backend(struct lb_value *val, dp_lb_port *lb_port)
{
	int ret = -1, k;

	for (k = 0; k < DP_LB_PORT_SIZE; k++) {
		if ((val->ports[k].port == lb_port->port) && (val->ports[k].protocol == lb_port->protocol))
			break;
		if (val->ports[k].port == 0)
			return ret;
	}

	if (val->back_end_cnt == 1) {
		for (k = 0; k < DP_LB_MAX_IPS_PER_VIP; k++)
			if (val->back_end_ips[k][0] != 0)
				break;
		if (k != DP_LB_MAX_IPS_PER_VIP)
			ret = k;
	} else {
		for (k = val->last_sel_pos; k < DP_LB_MAX_IPS_PER_VIP + val->last_sel_pos; k++)
			if ((val->back_end_ips[k % DP_LB_MAX_IPS_PER_VIP][0] != 0) && (k != val->last_sel_pos))
				break;

		if (k != (DP_LB_MAX_IPS_PER_VIP + val->last_sel_pos))
			ret = k % DP_LB_MAX_IPS_PER_VIP;
	}

	return ret;
}

uint8_t *dp_lb_get_backend_ip(uint32_t v_ip, uint32_t vni, uint16_t port, uint16_t proto)
{
	struct lb_value *lb_val = NULL;
	struct lb_key nkey = {
		.ip = v_ip,
		.vni = vni
	};
	dp_lb_port lb_port;
	int pos;

	if (rte_hash_lookup_data(ipv4_lb_tbl, &nkey, (void **)&lb_val) < 0)
		return NULL;

	/* TODO This is just temporary. Round robin.
	   This doesn't distribute the load evenly. 
	   Use maglev hashing and 5 Tuple fkey for 
	   backend selection */
	lb_port.port = port;
	lb_port.protocol = proto;
	pos = dp_lb_rr_backend(lb_val, &lb_port);
	if (pos < 0)
		return NULL;

	lb_val->last_sel_pos = pos;
	return (uint8_t *)&lb_val->back_end_ips[pos][0];
}

int dp_get_lb_back_ips(void *id_key, struct dp_grpc_responder *responder)
{
	struct lb_key *lb_k;
	struct lb_value *lb_val;
	dp_lb_backip *reply;

	if (DP_FAILED(rte_hash_lookup_data(id_map_lb_tbl, id_key, (void **)&lb_k)))
		return DP_GRPC_ERR_NOT_FOUND;

	if (DP_FAILED(rte_hash_lookup_data(ipv4_lb_tbl, lb_k, (void **)&lb_val)))
		return DP_GRPC_ERR_NO_BACKIP;

	dp_grpc_set_multireply(responder, sizeof(*reply));

	for (int i = 0; i < DP_LB_MAX_IPS_PER_VIP; ++i) {
		if (lb_val->back_end_ips[i][0] != 0) {
			reply = dp_grpc_add_reply(responder);
			if (!reply)
				return DP_GRPC_OK;  // do not fail, show truncated list
			rte_memcpy(reply->b_ip.addr6, &lb_val->back_end_ips[i][0], sizeof(reply->b_ip.addr6));
		}
	}
	return DP_GRPC_OK;
}

int dp_set_lb_back_ip(void *id_key, uint8_t *back_ip, uint8_t ip_size)
{
	struct lb_value *lb_val = NULL;
	struct lb_key *lb_k;
	int32_t pos;

	if (DP_FAILED(rte_hash_lookup_data(id_map_lb_tbl, id_key, (void **)&lb_k)))
		return DP_GRPC_ERR_NOT_FOUND;

	if (DP_FAILED(rte_hash_lookup_data(ipv4_lb_tbl, lb_k, (void **)&lb_val)))
		return DP_GRPC_ERR_NO_BACKIP;

	if (dp_lb_is_back_ip_inserted(lb_val, back_ip))
		return DP_GRPC_OK;

	pos = dp_lb_last_free_pos(lb_val);
	if (pos < 0)
		return DP_GRPC_ERR_LIMIT_REACHED;

	rte_memcpy(&lb_val->back_end_ips[pos][0], back_ip, ip_size);

	lb_val->back_end_cnt++;
	return DP_GRPC_OK;
}

int dp_del_lb_back_ip(void *id_key, uint8_t *back_ip)
{
	struct lb_value *lb_val;
	struct lb_key *lb_k;

	if (DP_FAILED(rte_hash_lookup_data(id_map_lb_tbl, id_key, (void **)&lb_k)))
		return DP_GRPC_ERR_NOT_FOUND;

	if (DP_FAILED(rte_hash_lookup_data(ipv4_lb_tbl, lb_k, (void **)&lb_val)))
		return DP_GRPC_ERR_NO_BACKIP;

	dp_lb_delete_back_ip(lb_val, back_ip);

	return DP_GRPC_OK;
}
