#include "dp_lpm.h"
#include "dp_flow.h"
#include "dp_util.h"
#include "node_api.h"
#include "dp_mbuf_dyn.h"
#include <rte_errno.h>
#include <rte_icmp.h>
#include "dp_nat.h"

static struct rte_hash *ipv4_flow_tbl = NULL;
static uint64_t timeout = 0;

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
	if (!ipv4_flow_tbl)
		rte_exit(EXIT_FAILURE, "create ipv4 flow table failed\n");
	timeout = rte_get_timer_hz() * DP_FLOW_DEFAULT_TIMEOUT;
}

void dp_build_flow_key(struct flow_key *key /* out */, struct rte_mbuf *m /* in */)
{
	struct dp_flow *df_ptr = get_dp_flow_ptr(m);

	key->ip_dst = rte_be_to_cpu_32(df_ptr->dst.dst_addr);
	key->ip_src = rte_be_to_cpu_32(df_ptr->src.src_addr);

	key->proto = df_ptr->l4_type;

	switch (df_ptr->l4_type) {
	case IPPROTO_TCP:
		key->port_dst = rte_be_to_cpu_16(df_ptr->dst_port);
		key->src.port_src = rte_be_to_cpu_16(df_ptr->src_port);
		break;
	case IPPROTO_UDP:
		key->port_dst = rte_be_to_cpu_16(df_ptr->dst_port);
		key->src.port_src = rte_be_to_cpu_16(df_ptr->src_port);
		break;
	case IPPROTO_ICMP:
		key->port_dst = 0;
		key->src.type_src = df_ptr->icmp_type;
		break;
	default:
		key->port_dst = 0;
		key->src.port_src = 0;
		break;
	}
}

void dp_invert_flow_key(struct flow_key *key /* in / out */)
{
	uint32_t ip_tmp;
	uint16_t port_tmp;

	ip_tmp = key->ip_src;
	key->ip_src = key->ip_dst;
	key->ip_dst = ip_tmp;
	if ((key->proto == IPPROTO_TCP) || (key->proto == IPPROTO_UDP)) {
		port_tmp = key->src.port_src;
		key->src.port_src = key->port_dst;
		key->port_dst = port_tmp;
	} else if (key->proto == IPPROTO_ICMP) {
		if (key->src.type_src == RTE_IP_ICMP_ECHO_REPLY)
			key->src.type_src = RTE_IP_ICMP_ECHO_REQUEST;
		if (key->src.type_src == RTE_IP_ICMP_ECHO_REQUEST)
			key->src.type_src = RTE_IP_ICMP_ECHO_REPLY;
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
		rte_exit(EXIT_FAILURE, "flow table for port add key failed\n");
}

void dp_delete_flow(struct flow_key *key)
{
	int pos;

	pos = rte_hash_del_key(ipv4_flow_tbl, key);
	if (pos < 0)
		printf("Hash key already deleted\n");
	else
		rte_hash_free_key_with_position(ipv4_flow_tbl, pos);
}

void dp_add_flow_data(struct flow_key *key, void *data)
{
	if (rte_hash_add_key_data(ipv4_flow_tbl, key, data) < 0)
		rte_exit(EXIT_FAILURE, "flow table for port add data failed\n");
}

void dp_get_flow_data(struct flow_key *key, void **data)
{
	if (rte_hash_lookup_data(ipv4_flow_tbl, key, data) < 0)
		data = NULL;
}

bool dp_are_flows_identical(struct flow_key *key1, struct flow_key *key2)
{

	if ((key1->proto != key2->proto) || (key1->ip_src != key2->ip_src)
		|| (key1->ip_dst != key2->ip_dst) || (key1->port_dst != key2->port_dst)
		|| (key1->src.port_src != key2->src.port_src))
		return false;

	return true;
}

void dp_free_flow(struct flow_value *cntrack)
{
	dp_free_network_nat_port(cntrack);
	dp_delete_flow(&cntrack->flow_key[cntrack->dir]);
	dp_delete_flow(&cntrack->flow_key[!cntrack->dir]);
	rte_free(cntrack);
}

void dp_free_network_nat_port(struct flow_value *cntrack)
{
	uint32_t nat_ip;
	uint32_t vni;
	uint16_t nat_port;

	if (cntrack->nat_info.nat_type == DP_FLOW_NAT_TYPE_NETWORK) {
		nat_ip = cntrack->flow_key[DP_FLOW_DIR_REPLY].ip_dst;
		vni = cntrack->nat_info.vni;
		nat_port = cntrack->flow_key[DP_FLOW_DIR_REPLY].port_dst;
		int ret = dp_remove_network_snat_port(nat_ip, nat_port, vni, cntrack->nat_info.l4_type);

		if (ret < 0) {
			printf("failed to remove an allocated network NAT port: %d, vni %d , with error code %d \n", nat_port, vni, ret);
		}
	}
}

void dp_process_aged_flows(int port_id)
{
	int nb_context, total = 0, idx;
	struct flow_age_ctx *agectx = NULL;
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
		agectx = (struct flow_age_ctx *)contexts[idx];
		if (!agectx)
			continue;
		rte_flow_destroy(port_id, agectx->rte_flow, &error);
		printf("Aged flow to sw table agectx: rteflow %p\n flowval: flowcnt %d  rte_flow inserted on port %d\n",
			 agectx->rte_flow, rte_atomic32_read(&agectx->cntrack->flow_cnt), port_id);
		if (rte_atomic32_dec_and_test(&agectx->cntrack->flow_cnt))
			dp_free_flow(agectx->cntrack);
		rte_free(agectx);
	}
free:
	rte_free(contexts);
}

void dp_process_aged_flows_non_offload(void)
{
	struct flow_value *flow_val = NULL;
	const void *next_key;
	uint32_t iter = 0;
	uint64_t cur;

	cur = rte_rdtsc();
	/* iterate through the hash table */
	while (rte_hash_iterate(ipv4_flow_tbl, &next_key,
						    (void **)&flow_val, &iter) >= 0) {
		if (unlikely((cur - flow_val->timestamp) > timeout))
			dp_free_flow(flow_val);
	}
}

hash_sig_t dp_get_flow_hash_value(struct flow_key *key)
{

	//It is not necessary to first test if this key exists, since for now, this function
	// is always called after either a flow is checked or added in the firewall node.
	return rte_hash_hash(ipv4_flow_tbl, key);

}
