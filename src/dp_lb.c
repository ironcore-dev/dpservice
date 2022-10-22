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
#include "dp_util.h"
#include "dp_lb.h"

struct rte_hash_parameters ipv4_lb_table_params = {
	.name = NULL,
	.entries = DP_LB_TABLE_MAX,
	.key_len =  sizeof(struct lb_key),
	.hash_func = rte_jhash,
	.hash_func_init_val = 0xfee1900d,
	.extra_flag = 0,
};

struct rte_hash_parameters lb_id_map_table_params = {
	.name = NULL,
	.entries = DP_LB_TABLE_MAX,
	.key_len =  DP_LB_ID_SIZE,
	.hash_func = rte_jhash,
	.hash_func_init_val = 0xfee1900e,
	.extra_flag = 0,
};

static struct rte_hash *ipv4_lb_tbl = NULL;
static struct rte_hash *id_map_lb_tbl = NULL;

void dp_init_lb_tables(int socket_id)
{
	char s[64];

	snprintf(s, sizeof(s), "ipv4_lb_table_%u", socket_id);
	ipv4_lb_table_params.name = s;
	ipv4_lb_table_params.socket_id = socket_id;
	ipv4_lb_tbl = rte_hash_create(&ipv4_lb_table_params);
	if(!ipv4_lb_tbl)
		rte_exit(EXIT_FAILURE, "create ipv4 lb table failed\n");

	snprintf(s, sizeof(s), "lb_id_map_table_%u", socket_id);
	lb_id_map_table_params.name = s;
	lb_id_map_table_params.socket_id = socket_id;
	id_map_lb_tbl = rte_hash_create(&lb_id_map_table_params);
	if (!id_map_lb_tbl)
		rte_exit(EXIT_FAILURE, "create id map lb table failed\n");
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

int dp_create_lb(void *id_key, uint32_t v_ip, uint32_t vni, struct dp_lb_port ports[])
{
	struct lb_value *lb_val = NULL;
	struct lb_key nkey;
	uint32_t i;

	nkey.ip = v_ip;
	nkey.vni = vni;

	lb_val = rte_zmalloc("lb_val", sizeof(struct lb_value), RTE_CACHE_LINE_SIZE);
	if (!lb_val)
		goto err;

	if (rte_hash_add_key_data(ipv4_lb_tbl, &nkey, lb_val) < 0)
		goto out;

	if (dp_map_lb_handle(id_key, &nkey, lb_val))
		goto out;

	for (i = 0; i < DP_LB_PORT_SIZE; i++) {
		lb_val->ports[i].port = ntohs(ports[i].port);
		lb_val->ports[i].protocol = ports[i].protocol;
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
		DPS_LOG(WARNING, DPSERVICE, "LB hash key already deleted \n");
	else
		rte_hash_free_key_with_position(ipv4_lb_tbl, pos);

	rte_free(lb_k);
	pos = rte_hash_del_key(id_map_lb_tbl, id_key);
	if (pos < 0)
		DPS_LOG(WARNING, DPSERVICE, "LB id map hash key already deleted \n");
	else
		rte_hash_free_key_with_position(id_map_lb_tbl, pos);

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