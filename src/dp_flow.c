#include "dp_lpm.h"
#include "dp_flow.h"
#include "dp_util.h"
#include "node_api.h"
#include "dp_mbuf_dyn.h"
#include <rte_errno.h>

static struct rte_hash *ipv4_flow_tbl = NULL;

void dp_init_flowtable(int socket_id)
{
	struct rte_hash_parameters ipv4_table_params = {
		.name = NULL,
		.entries = FLOW_MAX,
		.key_len =  sizeof(struct flow_key),
		.hash_func = rte_jhash,
		.hash_func_init_val = 0xfee1900d,
		.extra_flag = 0,
	};
	char s[64];

	snprintf(s, sizeof(s), "ipv4_flow_table_%u", socket_id);
	ipv4_table_params.name = s;
	ipv4_table_params.socket_id = socket_id;
	ipv4_flow_tbl = rte_hash_create(&ipv4_table_params);
	if(!ipv4_flow_tbl)
		rte_exit(EXIT_FAILURE, "create ipv4 flow table failed\n");
}

void dp_build_flow_key(struct flow_key *key /* out */, struct rte_mbuf *m /* in */)
{
	struct dp_flow *df_ptr = get_dp_flow_ptr(m);

	key->ip_dst = rte_be_to_cpu_32(df_ptr->dst.dst_addr);

	if (df_ptr->flags.nat == DP_NAT_SNAT) {
		key->ip_src = rte_be_to_cpu_32(dp_get_vm_nat_ip(m->port));
	} else {
		key->ip_src = rte_be_to_cpu_32(df_ptr->src.src_addr);
	}
	key->proto = df_ptr->l4_type;

	if (df_ptr->flags.nat == DP_NAT_DNAT || df_ptr->flags.nat == DP_NAT_SNAT) {
		key->port_start = 0;
		key->port_end = 0;
	} else {
		key->port_start = m->port;
		key->port_end = df_ptr->nxt_hop;
	}

	switch (df_ptr->l4_type) {
		case IPPROTO_TCP:
				key->port_dst = rte_be_to_cpu_16(df_ptr->dst_port);
				key->port_src = rte_be_to_cpu_16(df_ptr->src_port);
				break;

		case IPPROTO_UDP:
				key->port_dst = rte_be_to_cpu_16(df_ptr->dst_port);
				key->port_src = rte_be_to_cpu_16(df_ptr->src_port);
				break;

		default:
				key->port_dst = 0;
				key->port_src = 0;
				break;
	}

	if (key->ip_src > key->ip_dst) {
		uint32_t ip_tmp;
		uint16_t port_tmp;
		ip_tmp = key->ip_src;
		key->ip_src = key->ip_dst;
		key->ip_dst = ip_tmp;
		port_tmp = key->port_src;
		key->port_src = key->port_dst;
		key->port_dst = port_tmp;
		port_tmp = key->port_start;
		key->port_start = key->port_end;
		key->port_end = port_tmp;
	}
}

bool dp_flow_exists(struct flow_key *key)
{
	int ret;

	ret = rte_hash_lookup(ipv4_flow_tbl, key);
	if (ret < 0)
		return false;
	return true;
}

void dp_add_flow(struct flow_key *key)
{
	if (rte_hash_add_key(ipv4_flow_tbl, key) < 0)
		rte_exit(EXIT_FAILURE, "flow table for port %d add key failed\n", key->port_start);
}

void dp_delete_flow(struct flow_key *key)
{
	int pos;

	pos = rte_hash_del_key(ipv4_flow_tbl, key);
	if (pos < 0)
		printf("Hash key already deleted \n");
	else
		rte_hash_free_key_with_position(ipv4_flow_tbl, pos);
}

void dp_add_flow_data(struct flow_key *key, void* data)
{
	if (rte_hash_add_key_data(ipv4_flow_tbl, key, data) < 0)
		rte_exit(EXIT_FAILURE, "flow table for port %d add data failed\n", key->port_start);
}

void dp_get_flow_data(struct flow_key *key, void **data)
{
	if (rte_hash_lookup_data(ipv4_flow_tbl, key, data) < 0)
		data = NULL;
}

void dp_process_aged_flows(int port_id)
{
	int nb_context, total = 0, idx;
	struct flow_age_ctx *agectx = NULL;
	struct flow_value *flow_val = NULL;
	struct rte_flow_error error;
	void **contexts;

	total = rte_flow_get_aged_flows(port_id, NULL, 0, &error);

	if (total <= 0)
		return;

	contexts = rte_zmalloc("aged_ctx", sizeof(void *) * total,
			       RTE_CACHE_LINE_SIZE);
	if (contexts == NULL)
		return;

	nb_context = rte_flow_get_aged_flows(port_id, contexts,
					     total, &error);
	if (nb_context != total)
		goto free;

	for (idx = 0; idx < nb_context; idx++) {
		agectx = (struct flow_age_ctx*)contexts[idx];
		if (!agectx)
			continue;
		rte_flow_destroy(port_id, agectx->rteflow, &error);
		dp_get_flow_data(&agectx->fkey, (void**)&flow_val);
		printf("Aged flow to sw table agectx: rteflow %p \n flowval: flowcnt %d hash key %p  rte_flow inserted on port %d\n", 
			 agectx->rteflow, rte_atomic32_read(&flow_val->flow_cnt), &agectx->fkey, port_id);
		if (!flow_val) {
			rte_free(agectx);
			continue;
		}
		if (rte_atomic32_dec_and_test(&flow_val->flow_cnt)) {
			dp_delete_flow(&agectx->fkey);
			rte_free(flow_val);
		}
		rte_free(agectx);
	}

free:
	rte_free(contexts);
}
