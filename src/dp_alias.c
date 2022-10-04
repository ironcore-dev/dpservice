#include <rte_malloc.h>
#include "dp_alias.h"

static struct rte_hash *alias_handle_tbl = NULL;

void dp_init_alias_handle_tbl(int socket_id)
{
	struct rte_hash_parameters handle_table_params = {
		.name = NULL,
		.entries = DP_ALIAS_MAX_TABLE_SIZE,
		.key_len =  DP_ALIAS_IPV6_ADDR_SIZE,
		.hash_func = rte_jhash,
		.hash_func_init_val = 0xfee1900a,
		.extra_flag = 0,
	};
	char s[64];

	snprintf(s, sizeof(s), "alias_handle_table_%u", socket_id);
	handle_table_params.name = s;
	handle_table_params.socket_id = socket_id;
	alias_handle_tbl = rte_hash_create(&handle_table_params);
	if (!alias_handle_tbl)
		rte_exit(EXIT_FAILURE, "create alias handle table failed\n");
}

int dp_map_alias_handle(void *key, uint16_t portid)
{
	uint16_t *p_port_id;

	p_port_id = rte_zmalloc("alias_handle_mapping", sizeof(uint16_t), RTE_CACHE_LINE_SIZE);
	if (!p_port_id) {
		printf("alias handle for port %d malloc data failed\n", portid);
		return EXIT_FAILURE;
	}

	RTE_VERIFY(portid < DP_MAX_PORTS);
	if (rte_hash_lookup(alias_handle_tbl, key) >= 0)
		goto err;

	*p_port_id = portid;
	if (rte_hash_add_key_data(alias_handle_tbl, key, p_port_id) < 0) {
		printf("alias handle for port %d add data failed\n", portid);
		goto err;
	}
	return EXIT_SUCCESS;

err:
	rte_free(p_port_id);
	return EXIT_FAILURE;
}

int dp_get_portid_with_alias_handle(void *key)
{
	uint16_t *p_port_id;
	uint16_t ret_val;

	if (rte_hash_lookup_data(alias_handle_tbl, key, (void **)&p_port_id) < 0)
		return -1;
	ret_val = *p_port_id;

	return ret_val;
}

void dp_del_portid_with_alias_handle(void *key)
{
	uint16_t *p_port_id = NULL;

	rte_hash_lookup_data(alias_handle_tbl, key, (void **)&p_port_id);
	rte_free(p_port_id);
	rte_hash_del_key(alias_handle_tbl, key);
}