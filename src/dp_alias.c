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

int dp_map_alias_handle(void *key, dp_alias_value *val)
{
	dp_alias_value *temp_val;

	temp_val = rte_zmalloc("alias_handle_mapping", sizeof(dp_alias_value), RTE_CACHE_LINE_SIZE);
	if (!temp_val) {
		printf("alias handle for port %d malloc data failed\n", val->portid);
		return EXIT_FAILURE;
	}

	RTE_VERIFY(val->portid < DP_MAX_PORTS);
	if (rte_hash_lookup(alias_handle_tbl, key) >= 0)
		goto err;

	*temp_val = *val;
	if (rte_hash_add_key_data(alias_handle_tbl, key, temp_val) < 0) {
		printf("alias handle for port %d add data failed\n", temp_val->portid);
		goto err;
	}
	return EXIT_SUCCESS;

err:
	rte_free(temp_val);
	return EXIT_FAILURE;
}

int dp_get_portid_with_alias_handle(void *key)
{
	dp_alias_value *temp_val;
	uint16_t ret_val;

	if (rte_hash_lookup_data(alias_handle_tbl, key, (void **)&temp_val) < 0)
		return -1;
	ret_val = temp_val->portid;

	return ret_val;
}

void dp_del_portid_with_alias_handle(dp_alias_value *val)
{
	dp_alias_value *temp_val = NULL;
	uint32_t iter = 0;
	int32_t ret;
	void *key;

	while (true) {
		ret = rte_hash_iterate(alias_handle_tbl, (const void **)&key, (void **)&temp_val, &iter);

		if (ret == -ENOENT)
			break;

		if ((val->portid == temp_val->portid) && (val->ip == temp_val->ip) && (val->length == temp_val->length)) {
			rte_free(temp_val);
			rte_hash_del_key(alias_handle_tbl, key);
		}
	}
}

int dp_list_alias_routes(struct rte_mbuf *m, uint16_t portid, struct rte_mbuf *rep_arr[])
{
	int8_t rep_arr_size = DP_MBUF_ARR_SIZE;
	struct rte_mbuf *m_new, *m_curr = m;
	dp_alias_value *temp_val;
	uint16_t msg_per_buf;
	dp_route *rp_route;
	uint32_t iter = 0;
	dp_reply *rep;
	int32_t ret;
	void *key;

	if (rte_hash_count(alias_handle_tbl) == 0)
		goto err;

	msg_per_buf = dp_first_mbuf_to_grpc_arr(m_curr, rep_arr,
										    &rep_arr_size, sizeof(dp_route));
	rep = rte_pktmbuf_mtod(m_curr, dp_reply*);

	while (true) {
		ret = rte_hash_iterate(alias_handle_tbl, (const void **)&key, (void **)&temp_val, &iter);

		if (ret == -ENOENT)
			break;

		if (portid != temp_val->portid)
			continue;

		if (rep->com_head.msg_count &&
			(rep->com_head.msg_count % msg_per_buf == 0)) {

			m_new = dp_add_mbuf_to_grpc_arr(m_curr, rep_arr, &rep_arr_size);
			if (!m_new)
				break;
			m_curr = m_new;
			rep = rte_pktmbuf_mtod(m_new, dp_reply*);
		}
		rp_route = &((&rep->route)[rep->com_head.msg_count % msg_per_buf]);
		rep->com_head.msg_count++;

		rp_route->pfx_ip_type = RTE_ETHER_TYPE_IPV4;
		rp_route->pfx_ip.addr = temp_val->ip;
		rp_route->pfx_length = temp_val->length;
		memcpy(rp_route->trgt_ip.addr6, key, sizeof(rp_route->trgt_ip.addr6));
	}

	if (rep_arr_size < 0) {
		dp_last_mbuf_from_grpc_arr(m_curr, rep_arr);
		return EXIT_SUCCESS;
	}

err:
	rep_arr[--rep_arr_size] = m_curr;

	return EXIT_SUCCESS;
}