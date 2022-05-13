#include <time.h>
#include <stdlib.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_common.h>
#include <rte_errno.h>
#include <rte_malloc.h>
#include "dp_flow.h"
#include "dp_lb.h"

static struct rte_hash *ipv4_lb_tbl = NULL;

void dp_init_lb_tables(int socket_id)
{
	struct rte_hash_parameters ipv4_lb_table_params = {
		.name = NULL,
		.entries = DP_LB_TABLE_MAX,
		.key_len =  sizeof(struct lb_key),
		.hash_func = rte_jhash,
		.hash_func_init_val = 0xfee1900d,
		.extra_flag = 0,
	};
	char s[64];

	snprintf(s, sizeof(s), "ipv4_lb_table_%u", socket_id);
	ipv4_lb_table_params.name = s;
	ipv4_lb_table_params.socket_id = socket_id;
	ipv4_lb_tbl = rte_hash_create(&ipv4_lb_table_params);
	if(!ipv4_lb_tbl)
		rte_exit(EXIT_FAILURE, "create ipv4 lb table failed\n");
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

uint32_t dp_get_lb_ip(uint32_t vm_ip, uint32_t vni)
{
	//struct lb_key nkey;
	uint32_t *lb_ip = NULL;
/*
	nkey.ip = vm_ip;
	nkey.vni = vni;

	if (rte_hash_lookup_data(ipv4_lb_tbl, &nkey, (void**)&lb_ip) < 0)
		return 0;*/

	return *lb_ip;
}

static int dp_lb_last_free_pos(struct lb_value *val)
{
	int ret = -1, k;

	for (k = 0; k < DP_LB_MAX_IPS_PER_VIP; k++) {
		if (val->back_end_ips[k] == 0)
			break;
	}
	if (k != DP_LB_MAX_IPS_PER_VIP)
		ret = k;

	return ret;
}

static void dp_lb_delete_back_ip(struct lb_value *val, uint32_t b_ip)
{
	int k;

	for (k = 0; k < DP_LB_MAX_IPS_PER_VIP; k++) {
		if (val->back_end_ips[k] == b_ip) {
			val->back_end_ips[k] = 0;
			break;
		}
	}
}

static bool dp_lb_back_ips_exist(struct lb_value *val)
{
	int k;

	for (k = 0; k < DP_LB_MAX_IPS_PER_VIP; k++) {
		if (val->back_end_ips[k] != 0)
			break;
	}
	if (k != DP_LB_MAX_IPS_PER_VIP)
		return true;

	return false;
}

static int dp_lb_rr_backend(struct lb_value *val)
{
	int ret = -1, k;

	if (val->back_end_cnt == 1) {
		for (k = 0; k < DP_LB_MAX_IPS_PER_VIP; k++)
			if (val->back_end_ips[k] != 0)
				break;
		if (k != DP_LB_MAX_IPS_PER_VIP)
			ret = k;
	} else {
		for (k = val->last_sel_pos; k < DP_LB_MAX_IPS_PER_VIP + val->last_sel_pos; k++)
			if ((val->back_end_ips[k % DP_LB_MAX_IPS_PER_VIP] != 0) && (k != val->last_sel_pos))
				break;

		if (k != (DP_LB_MAX_IPS_PER_VIP + val->last_sel_pos))
			ret = k % DP_LB_MAX_IPS_PER_VIP;
	}

	return ret;
}

uint32_t dp_lb_get_backend_ip(uint32_t v_ip, uint32_t vni, struct flow_key *fkey)
{
	struct lb_value *lb_val = NULL;
	struct lb_key nkey;
	int pos, ret = 0;

	nkey.ip = v_ip;
	nkey.vni = vni;

	if (rte_hash_lookup_data(ipv4_lb_tbl, &nkey, (void**)&lb_val) < 0)
		goto out;

	/* TODO This is just temporary. Round robin.
	   This doesn't distribute the load evenly. 
	   Use maglev hashing and 5 Tuple fkey for 
	   backend selection */
	pos = dp_lb_rr_backend(lb_val);

	if (pos < 0)
		goto out;

	lb_val->last_sel_pos = pos;
	ret = lb_val->back_end_ips[pos];

out:
	return ret;
}

void dp_get_lb_back_ips(uint32_t v_ip, uint32_t vni, struct dp_reply *rep)
{
	struct lb_value *lb_val = NULL;
	struct lb_key nkey;
	uint32_t *rp_b_ip;
	int k;

	if (!dp_is_ip_lb(v_ip, vni))
		return;

	nkey.ip = v_ip;
	nkey.vni = vni;
	rep->com_head.msg_count = 0;

	if (rte_hash_lookup_data(ipv4_lb_tbl, &nkey, (void**)&lb_val) < 0)
		return;

	for (k = 0; k < DP_LB_MAX_IPS_PER_VIP; k++) {
		if (lb_val->back_end_ips[k] != 0) {
			rp_b_ip = &((&rep->back_ip)[rep->com_head.msg_count]);
			rep->com_head.msg_count++;
			*rp_b_ip = lb_val->back_end_ips[k];
		}
	}
}

int dp_set_lb_back_ip(uint32_t v_ip, uint32_t back_ip, uint32_t vni)
{
	struct lb_value *lb_val = NULL;
	struct lb_key nkey;
	int pos;

	nkey.ip = v_ip;
	nkey.vni = vni;

	if (!dp_is_ip_lb(v_ip, vni)) {
		if (rte_hash_add_key(ipv4_lb_tbl, &nkey) < 0)
			goto err;

		lb_val = rte_zmalloc("lb_val", sizeof(struct lb_value), RTE_CACHE_LINE_SIZE);
		if (!lb_val)
			goto err_key;
		lb_val->vip_maglev_tbl = NULL;
		pos = dp_lb_last_free_pos(lb_val);
		if (pos < 0)
			goto out;
		if (rte_hash_add_key_data(ipv4_lb_tbl, &nkey, lb_val) < 0)
			goto out;
		lb_val->back_end_ips[pos] = back_ip;
	} else {
		if (rte_hash_lookup_data(ipv4_lb_tbl, &nkey, (void**)&lb_val) < 0)
			goto err;
		pos = dp_lb_last_free_pos(lb_val);
		if (pos < 0)
			goto err;
		lb_val->back_end_ips[pos] = back_ip;
	}
	lb_val->back_end_cnt++;
	return EXIT_SUCCESS;
out:
	rte_free(lb_val);
err_key:
	pos = rte_hash_del_key(ipv4_lb_tbl, &nkey);
	if (pos < 0)
		printf("LB hash key already deleted \n");
	else
		rte_hash_free_key_with_position(ipv4_lb_tbl, pos);
err:
	printf("lb table add ip failed\n");
	return EXIT_FAILURE;
}

int dp_del_lb_back_ip(uint32_t vm_ip, uint32_t back_ip, uint32_t vni)
{
	int ret = EXIT_SUCCESS;
	struct lb_value *lb_val;
	struct lb_key nkey;
	int pos;

	nkey.ip = vm_ip;
	nkey.vni = vni;

	if (!dp_is_ip_lb(vm_ip, vni)) {
		ret = EXIT_FAILURE;
		goto out;
	}

	if (rte_hash_lookup_data(ipv4_lb_tbl, &nkey, (void**)&lb_val) < 0)
		goto clean_key;

	dp_lb_delete_back_ip(lb_val, back_ip);

	if (dp_lb_back_ips_exist(lb_val))
		goto out;

	rte_free(lb_val);

clean_key:
	pos = rte_hash_del_key(ipv4_lb_tbl, &nkey);
	if (pos < 0)
		printf("LB hash key already deleted \n");
	else
		rte_hash_free_key_with_position(ipv4_lb_tbl, pos);
out:
	return ret;
}