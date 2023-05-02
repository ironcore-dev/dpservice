#include <time.h>
#include <stdlib.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_common.h>
#include <rte_errno.h>
#include <rte_malloc.h>
#include <rte_rib6.h>
#include "dp_error.h"
#include "dp_flow.h"
#include "dp_log.h"
#include "dp_lb.h"

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

	lb_k = rte_zmalloc("lb_id_mapping", sizeof(struct lb_key), RTE_CACHE_LINE_SIZE);
	if (!lb_k) {
		printf("lb id mapping malloc data failed\n");
		return EXIT_FAILURE;
	}

	rte_memcpy(l_val->lb_id, id_key, DP_LB_ID_SIZE);
	*lb_k = *l_key;
	if (rte_hash_add_key_data(id_map_lb_tbl, id_key, lb_k) < 0) {
		printf("lb id add data failed\n");
		goto err;
	}
	return EXIT_SUCCESS;

err:
	rte_free(lb_k);
	return EXIT_FAILURE;
}

int dp_create_lb(dp_add_lb *add_lb, uint8_t *ul_ip)
{
	struct lb_value *lb_val = NULL;
	struct lb_key nkey;
	uint32_t i;

	nkey.ip = ntohl(add_lb->vip.vip_addr);
	nkey.vni = add_lb->vni;

	lb_val = rte_zmalloc("lb_val", sizeof(struct lb_value), RTE_CACHE_LINE_SIZE);
	if (!lb_val)
		goto err;

	if (rte_hash_add_key_data(ipv4_lb_tbl, &nkey, lb_val) < 0)
		goto out;

	if (dp_map_lb_handle((void *)add_lb->lb_id, &nkey, lb_val))
		goto out;

	rte_memcpy(lb_val->lb_ul_addr, ul_ip, DP_VNF_IPV6_ADDR_SIZE);
	for (i = 0; i < DP_LB_PORT_SIZE; i++) {
		lb_val->ports[i].port = ntohs(add_lb->lbports[i].port);
		lb_val->ports[i].protocol = add_lb->lbports[i].protocol;
	}

	return EXIT_SUCCESS;
out:
	rte_free(lb_val);
err:
	return EXIT_FAILURE;
}

int dp_get_lb(void *id_key, dp_lb *list_lb)
{
	struct lb_value *lb_val = NULL;
	struct lb_key *lb_k;
	int32_t i;

	if (rte_hash_lookup_data(id_map_lb_tbl, id_key, (void **)&lb_k) < 0)
		return DP_ERROR_GET_LB_ID_ERR;

	if (rte_hash_lookup_data(ipv4_lb_tbl, lb_k, (void **)&lb_val) < 0)
		return DP_ERROR_GET_LB_BACK_IP_ERR;

	list_lb->ip_type = RTE_ETHER_TYPE_IPV4;
	list_lb->vni = lb_k->vni;
	list_lb->vip.vip_addr = htonl(lb_k->ip);
	rte_memcpy(list_lb->ul_addr6, lb_val->lb_ul_addr, DP_VNF_IPV6_ADDR_SIZE);

	for (i = 0; i < DP_LB_PORT_SIZE; i++) {
		list_lb->lbports[i].port = htons(lb_val->ports[i].port);
		list_lb->lbports[i].protocol = lb_val->ports[i].protocol;
	}

	return EXIT_SUCCESS;
}

int dp_delete_lb(void *id_key)
{
	struct lb_value *lb_val = NULL;
	int res = EXIT_SUCCESS;
	struct lb_key *lb_k;
	int32_t pos;

	if (rte_hash_lookup_data(id_map_lb_tbl, id_key, (void **)&lb_k) < 0) {
		res = DP_ERROR_DEL_LB_ID_ERR;
		goto err_id;
	}

	if (rte_hash_lookup_data(ipv4_lb_tbl, lb_k, (void **)&lb_val) < 0) {
		res = DP_ERROR_DEL_LB_BACK_IP_ERR;
		goto err_back_ip;
	}

	rte_free(lb_val);
	pos = rte_hash_del_key(ipv4_lb_tbl, lb_k);
	if (pos < 0)
		DPS_LOG_WARNING("LB hash key already deleted");

	rte_free(lb_k);
	pos = rte_hash_del_key(id_map_lb_tbl, id_key);
	if (pos < 0)
		DPS_LOG_WARNING("LB id map hash key already deleted");

	return EXIT_SUCCESS;

err_back_ip:
	rte_free(lb_val);
err_id:
	return res;
}

bool dp_is_lb_enabled()
{
	return (rte_hash_count(ipv4_lb_tbl) > 0);
}

bool dp_is_ip_lb(uint32_t vm_ip, uint32_t vni)
{
	struct lb_key nkey;
	int ret;

	nkey.ip = vm_ip;
	nkey.vni = vni;

	ret = rte_hash_lookup(ipv4_lb_tbl, &nkey);
	if (ret < 0)
		return false;
	return true;
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
	int k;

	for (k = 0; k < DP_LB_MAX_IPS_PER_VIP; k++) {
		if (rte_rib6_is_equal((uint8_t *)&val->back_end_ips[k][0], b_ip)) {
			memset(&val->back_end_ips[k][0], 0, 16);
			val->back_end_cnt--;
			break;
		}
	}
}

static bool dp_lb_is_back_ip_inserted(struct lb_value *val, uint8_t *b_ip)
{
	int k;

	for (k = 0; k < DP_LB_MAX_IPS_PER_VIP; k++)
		if (rte_rib6_is_equal((uint8_t *)&val->back_end_ips[k][0], b_ip))
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
	uint8_t *ret = NULL;
	struct lb_key nkey;
	dp_lb_port lb_port;
	int pos;

	nkey.ip = v_ip;
	nkey.vni = vni;

	if (rte_hash_lookup_data(ipv4_lb_tbl, &nkey, (void **)&lb_val) < 0)
		goto out;

	/* TODO This is just temporary. Round robin.
	   This doesn't distribute the load evenly. 
	   Use maglev hashing and 5 Tuple fkey for 
	   backend selection */
	lb_port.port = port;
	lb_port.protocol = proto;
	pos = dp_lb_rr_backend(lb_val, &lb_port);

	if (pos < 0)
		goto out;

	lb_val->last_sel_pos = pos;
	ret = (uint8_t *)&lb_val->back_end_ips[pos][0];

out:
	return ret;
}

void dp_get_lb_back_ips(void *id_key, struct dp_reply *rep)
{
	struct lb_value *lb_val = NULL;
	struct lb_key *lb_k;
	uint8_t *rp_b_ip6;
	int k;

	if (rte_hash_lookup_data(id_map_lb_tbl, id_key, (void **)&lb_k) < 0)
		return;

	if (rte_hash_lookup_data(ipv4_lb_tbl, lb_k, (void **)&lb_val) < 0)
		return;

	rep->com_head.msg_count = 0;

	rp_b_ip6 = &rep->back_ip.b_ip.addr6[0];
	for (k = 0; k < DP_LB_MAX_IPS_PER_VIP; k++) {
		if (lb_val->back_end_ips[k][0] != 0) {
			rep->com_head.msg_count++;
			rte_memcpy(rp_b_ip6, &lb_val->back_end_ips[k][0], sizeof(rep->back_ip.b_ip.addr6));
			rp_b_ip6 += sizeof(rep->back_ip.b_ip.addr6);
		}
	}
}

int dp_set_lb_back_ip(void *id_key, uint8_t *back_ip, uint8_t ip_size)
{
	struct lb_value *lb_val = NULL;
	struct lb_key *lb_k;
	int32_t pos;

	if (rte_hash_lookup_data(id_map_lb_tbl, id_key, (void **)&lb_k) < 0)
		goto err;

	if (rte_hash_lookup_data(ipv4_lb_tbl, lb_k, (void **)&lb_val) < 0)
		goto err;

	if (dp_lb_is_back_ip_inserted(lb_val, back_ip))
		return EXIT_SUCCESS;

	pos = dp_lb_last_free_pos(lb_val);
	if (pos < 0)
		goto err;
	rte_memcpy(&lb_val->back_end_ips[pos][0], back_ip, ip_size);

	lb_val->back_end_cnt++;
	return EXIT_SUCCESS;
err:
	printf("lb table add ip failed\n");
	return EXIT_FAILURE;
}

int dp_del_lb_back_ip(void *id_key, uint8_t *back_ip)
{
	int ret = EXIT_SUCCESS;
	struct lb_value *lb_val;
	struct lb_key *lb_k;

	if (rte_hash_lookup_data(id_map_lb_tbl, id_key, (void **)&lb_k) < 0)
		goto out;

	if (rte_hash_lookup_data(ipv4_lb_tbl, lb_k, (void **)&lb_val) < 0)
		goto out;

	dp_lb_delete_back_ip(lb_val, back_ip);

out:
	return ret;
}

bool dp_is_vni_lb_available(int vni)
{
	struct lb_key *temp_val;
	uint32_t iter = 0;
	uint64_t *key;
	int32_t ret;

	if (rte_hash_count(id_map_lb_tbl) == 0)
		return false;

	while (true) {
		ret = rte_hash_iterate(id_map_lb_tbl, (const void **)&key, (void **)&temp_val, &iter);
		if (ret == -ENOENT)
			break;
		if (temp_val->vni == vni)
			return true;
	}

	return false;
}
