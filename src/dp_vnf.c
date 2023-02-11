#include <rte_malloc.h>
#include "dp_vnf.h"
#include "dp_error.h"

static struct rte_hash *vnf_handle_tbl = NULL;

int dp_vnf_init(int socket_id)
{
	vnf_handle_tbl = dp_create_jhash_table(DP_VNF_MAX_TABLE_SIZE, DP_VNF_IPV6_ADDR_SIZE,
										     "vnf_handle_table", socket_id);
	if (!vnf_handle_tbl)
		return DP_ERROR;

	return DP_OK;
}

int dp_map_vnf_handle(void *key, struct dp_vnf_value *val)
{
	struct dp_vnf_value *temp_val;

	temp_val = rte_zmalloc("vnf_handle_mapping", sizeof(struct dp_vnf_value), RTE_CACHE_LINE_SIZE);
	if (!temp_val) {
		printf("vnf handle for port %d malloc data failed\n", val->portid);
		return DP_ERROR;
	}

	RTE_VERIFY(val->portid < DP_MAX_PORTS);
	if (rte_hash_lookup(vnf_handle_tbl, key) >= 0)
		goto err;

	*temp_val = *val;
	if (rte_hash_add_key_data(vnf_handle_tbl, key, temp_val) < 0) {
		printf("vnf handle for port %d add data failed\n", temp_val->portid);
		goto err;
	}
	return DP_OK;

err:
	rte_free(temp_val);
	return DP_ERROR;
}

int dp_get_portid_with_vnf_key(void *key)
{
	struct dp_vnf_value *temp_val;
	uint16_t ret_val;

	if (rte_hash_lookup_data(vnf_handle_tbl, key, (void **)&temp_val) < 0)
		return -1;

	/*TODO (guvenc) remove this check */
	if (temp_val->v_type != DP_VNF_TYPE_LB_ALIAS_PFX)
		return -1;

	ret_val = temp_val->portid;

	return ret_val;
}

int dp_del_vnf_with_vnf_key(void *key)
{
	struct dp_vnf_value *temp_val;

	if (rte_hash_lookup_data(vnf_handle_tbl, key, (void **)&temp_val) < 0)
		return DP_ERROR;

	rte_free(temp_val);
	rte_hash_del_key(vnf_handle_tbl, key);

	return DP_OK;
}

void dp_del_vnf_with_value(struct dp_vnf_value *val)
{
	struct dp_vnf_value *temp_val = NULL;
	uint32_t iter = 0;
	int32_t ret;
	void *key;

	while (true) {
		ret = rte_hash_iterate(vnf_handle_tbl, (const void **)&key, (void **)&temp_val, &iter);

		if (ret == -ENOENT)
			break;

		if ((val->portid == temp_val->portid)
			&& (val->vnf.alias_pfx.ip == temp_val->vnf.alias_pfx.ip)
			&& (val->vnf.alias_pfx.length == temp_val->vnf.alias_pfx.length)
			&& (val->v_type == temp_val->v_type)
		) {
			rte_free(temp_val);
			rte_hash_del_key(vnf_handle_tbl, key);
		}
	}
}

int dp_list_vnf_alias_routes(struct rte_mbuf *m, uint16_t portid, enum vnf_type v_type, struct rte_mbuf *rep_arr[])
{
	int8_t rep_arr_size = DP_MBUF_ARR_SIZE;
	struct rte_mbuf *m_new, *m_curr = m;
	struct dp_vnf_value *temp_val;
	uint16_t msg_per_buf;
	dp_route *rp_route;
	uint32_t iter = 0;
	dp_reply *rep;
	int32_t ret;
	void *key;

	if (rte_hash_count(vnf_handle_tbl) == 0)
		goto err;

	msg_per_buf = dp_first_mbuf_to_grpc_arr(m_curr, rep_arr,
										    &rep_arr_size, sizeof(dp_route));
	rep = rte_pktmbuf_mtod(m_curr, dp_reply*);

	while (true) {
		ret = rte_hash_iterate(vnf_handle_tbl, (const void **)&key, (void **)&temp_val, &iter);

		if (ret == -ENOENT)
			break;

		if (portid != temp_val->portid)
			continue;

		if (temp_val->v_type != v_type)
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
		rp_route->pfx_ip.addr = temp_val->vnf.alias_pfx.ip;
		rp_route->pfx_length = temp_val->vnf.alias_pfx.length;
		rte_memcpy(rp_route->trgt_ip.addr6, key, sizeof(rp_route->trgt_ip.addr6));
	}

	if (rep_arr_size < 0) {
		dp_last_mbuf_from_grpc_arr(m_curr, rep_arr);
		return EXIT_SUCCESS;
	}

err:
	rep_arr[--rep_arr_size] = m_curr;

	return EXIT_SUCCESS;
}
