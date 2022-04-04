#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_common.h>
#include <rte_errno.h>
#include <rte_malloc.h>
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

uint32_t dp_get_vm_lb_ip(uint32_t vm_ip, uint32_t vni)
{
	struct lb_key nkey;
	uint32_t *lb_ip;

	nkey.ip = vm_ip;
	nkey.vni = vni;

	if (rte_hash_lookup_data(ipv4_lb_tbl, &nkey, (void**)&lb_ip) < 0)
		return 0;

	return *lb_ip;
}

void dp_set_vm_lb_ip(uint32_t vm_ip, uint32_t s_ip, uint32_t vni)
{
	struct lb_key nkey;
	uint32_t *lb_ip;

	nkey.ip = vm_ip;
	nkey.vni = vni;

	if (rte_hash_add_key(ipv4_lb_tbl, &nkey) < 0)
		goto err;

	lb_ip = rte_zmalloc("lb_val", sizeof(uint32_t), RTE_CACHE_LINE_SIZE);
	if (!lb_ip)
		goto err;

	*lb_ip = s_ip;
	if (rte_hash_add_key_data(ipv4_lb_tbl, &nkey, lb_ip) < 0)
		goto out;

	return;
out:
	rte_free(lb_ip);
err:
	printf("lb table add ip failed\n");
}

void dp_del_vm_lb_ip(uint32_t vm_ip, uint32_t vni)
{
	struct lb_key nkey;
	uint32_t *lb_ip;
	int pos;

	nkey.ip = vm_ip;
	nkey.vni = vni;

	if (rte_hash_lookup_data(ipv4_lb_tbl, &nkey, (void**)&lb_ip) < 0)
		return;
	rte_free(lb_ip);

	pos = rte_hash_del_key(ipv4_lb_tbl, &nkey);
	if (pos < 0)
		printf("LB hash key already deleted \n");
	else
		rte_hash_free_key_with_position(ipv4_lb_tbl, pos);
}