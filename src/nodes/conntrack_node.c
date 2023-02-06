#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_mbuf.h>
#include "dp_mbuf_dyn.h"
#include "dp_lpm.h"
#include "dp_flow.h"
#include "dp_log.h"
#include "rte_flow/dp_rte_flow.h"
#include "nodes/common_node.h"
#include "nodes/conntrack_node.h"
#include "nodes/dhcp_node.h"
#include "dp_nat.h"
#include "dp_vnf.h"
#include "dp_refcount.h"
#include <stdio.h>
#include <unistd.h>

static struct flow_key first_key = {0};
static struct flow_key second_key = {0};
static struct flow_key *prev_key, *curr_key;
static struct flow_value *prev_flow_val = NULL;

static int conntrack_node_init(const struct rte_graph *graph, struct rte_node *node)
{
	struct conntrack_node_ctx *ctx = (struct conntrack_node_ctx *)node->ctx;

	ctx->next = CONNTRACK_NEXT_DROP;

	RTE_SET_USED(graph);

	prev_key = NULL;
	curr_key = &first_key;

	return 0;
}

// static __rte_always_inline void set_flow_timeout_value(struct dp_flow *df_ptr, struct flow_value *flow_val)
// {
// 	flow_val->timeout_value = DP_FLOW_DEFAULT_TIMEOUT;
// }

static __rte_always_inline struct flow_value *flow_table_insert_entry(struct flow_key *key, struct dp_flow *df_ptr, struct rte_mbuf *m)
{
	struct flow_value *flow_val = NULL;

	flow_val = rte_zmalloc("flow_val", sizeof(struct flow_value), RTE_CACHE_LINE_SIZE);
	if (!flow_val)
		return flow_val;
	/* Add original direction to conntrack table */
	dp_add_flow(key);
	rte_atomic32_clear(&flow_val->flow_cnt);
	flow_val->flow_key[DP_FLOW_DIR_ORG] = *key;
	flow_val->flow_state = DP_FLOW_STATE_NEW;
	flow_val->flow_status = DP_FLOW_STATUS_NONE;
	flow_val->dir = DP_FLOW_DIR_ORG;
	flow_val->nat_info.nat_type = DP_FLOW_NAT_TYPE_NONE;
	// set_flow_timeout_value(df_ptr, flow_val);
	flow_val->timeout_value = DP_FLOW_DEFAULT_TIMEOUT;
	dp_ref_init(&flow_val->ref_count, dp_free_flow);
	dp_add_flow_data(key, flow_val);

	// Only the original flow (outgoing)'s hash value is recorded
	// Implicit casting from hash_sig_t to uint32_t!
	df_ptr->dp_flow_hash = dp_get_conntrack_flow_hash_value(key);

	dp_invert_flow_key(key);
	flow_val->flow_key[DP_FLOW_DIR_REPLY] = *key;
	dp_add_flow(key);
	dp_add_flow_data(key, flow_val);
	return flow_val;
}

static __rte_always_inline void change_flow_state_dir(struct flow_key *key, struct flow_value *flow_val, struct dp_flow *df_ptr)
{

	if (flow_val->nat_info.nat_type == DP_FLOW_NAT_TYPE_NETWORK_NEIGH) {
		if (dp_are_flows_identical(key, &flow_val->flow_key[DP_FLOW_DIR_ORG])) {
			if (flow_val->flow_state == DP_FLOW_STATE_NEW)
				flow_val->flow_state = DP_FLOW_STATE_ESTAB;
			flow_val->dir = DP_FLOW_DIR_ORG;
		}
	} else {
		if (dp_are_flows_identical(key, &flow_val->flow_key[DP_FLOW_DIR_REPLY])) {
			if (flow_val->flow_state == DP_FLOW_STATE_NEW)
				flow_val->flow_state = DP_FLOW_STATE_REPLY;
			
			flow_val->dir = DP_FLOW_DIR_REPLY;
		}

		if (dp_are_flows_identical(key, &flow_val->flow_key[DP_FLOW_DIR_ORG])) {
			if (flow_val->flow_state == DP_FLOW_STATE_REPLY)
				flow_val->flow_state = DP_FLOW_STATE_ESTAB;
			
			flow_val->dir = DP_FLOW_DIR_ORG;
		}
	}
	df_ptr->dp_flow_hash = dp_get_conntrack_flow_hash_value(key);
}

static __rte_always_inline bool dp_test_next_n_bytes_identical(const unsigned char *first_val, const unsigned char *second_val, uint8_t nr_bytes)
{

	for (uint8_t i = 0; i < nr_bytes; i++) {
		if ((first_val[i] ^ second_val[i]) > 0)
			return false;
	}

	return true;
}

static __rte_always_inline rte_edge_t dp_find_nxt_graph_node(struct dp_flow *df_ptr)
{
	if (df_ptr->flags.flow_type == DP_FLOW_TYPE_INCOMING) {
		switch (df_ptr->vnf_type) {
		case DP_VNF_TYPE_LB:
			return CONNTRACK_NEXT_LB;
			break;
		case DP_VNF_TYPE_VIP:
		case DP_VNF_TYPE_NAT:
			return CONNTRACK_NEXT_DNAT;
			break;
		case DP_VNF_TYPE_LB_ALIAS_PFX:
		case DP_VNF_TYPE_INTERFACE_IP:
		case DP_VNF_TYPE_ALIAS_PFX:
			return CONNTRACK_NEXT_FIREWALL;
			break;
		default:
			return CONNTRACK_NEXT_LB;
		}
	}
	return CONNTRACK_NEXT_DNAT;
}


static __rte_always_inline rte_edge_t get_next_index(struct rte_node *node, struct rte_mbuf *m)
{
	struct flow_value *flow_val = NULL;
	struct rte_ipv4_hdr *ipv4_hdr;
	struct dp_flow *df_ptr;
	struct flow_key *key;
	int key_search_result;
	bool key_cmp_result;

	df_ptr = get_dp_flow_ptr(m);
	ipv4_hdr = dp_get_ipv4_hdr(m);

	if (extract_inner_l3_header(m, ipv4_hdr, 0) < 0)
		return CONNTRACK_NEXT_DROP;

	if (extract_inner_l4_header(m, ipv4_hdr + 1, 0) < 0)
		return CONNTRACK_NEXT_DROP;

	if (df_ptr->l4_type == DP_IP_PROTO_UDP && ntohs(df_ptr->l4_info.trans_port.dst_port) == DP_BOOTP_SRV_PORT)
		return CONNTRACK_NEXT_DNAT;

	if (!dp_conf_is_conntrack_enabled())
		return CONNTRACK_NEXT_DNAT;

	if (df_ptr->l4_type == IPPROTO_TCP
		|| df_ptr->l4_type == IPPROTO_UDP
		|| df_ptr->l4_type == IPPROTO_ICMP
	) {
		key = curr_key;

		memset(key, 0, sizeof(struct flow_key));
		if (unlikely(dp_build_flow_key(key, m) < 0)) {
			DPNODE_LOG_WARNING(node, "Failed to build a flow key\n");
			return CONNTRACK_NEXT_DROP;
		}

		if (prev_key)
			key_cmp_result = dp_test_next_n_bytes_identical((const unsigned char *)prev_key,
													(const unsigned char *)curr_key,
													sizeof(struct flow_key));
		if (!prev_key || !key_cmp_result) {
			key_search_result = dp_get_flow_data(key, (void **)&flow_val);
			if (unlikely(key_search_result == -ENOENT)) {
				flow_val = flow_table_insert_entry(key, df_ptr, m);
				if (!flow_val) {
					DPNODE_LOG_WARNING(node, "Failed to add a flow table entry due to NULL flow_val pointer\n");
					return CONNTRACK_NEXT_DROP;
				}
			} else if (key_search_result == -EINVAL) {
				DPNODE_LOG_ERR(node, "Conntrack operation: hash key search failed due to invalid parameters\n");
				return CONNTRACK_NEXT_DROP;
			} else {
				change_flow_state_dir(key, flow_val, df_ptr);
			}
			prev_key = curr_key;
			if (curr_key == &first_key)
				curr_key = &second_key;
			else
				curr_key = &first_key;

			prev_flow_val = flow_val;
		} else {
			flow_val = prev_flow_val;
			change_flow_state_dir(key, flow_val, df_ptr);
		}

		flow_val->timestamp = rte_rdtsc();
		df_ptr->conntrack = flow_val;
	} else {
		return CONNTRACK_NEXT_DROP;
	}

	return dp_find_nxt_graph_node(df_ptr);
}

static uint16_t conntrack_node_process(struct rte_graph *graph,
									   struct rte_node *node,
									   void **objs,
									   uint16_t nb_objs)
{
	dp_foreach_graph_packet(graph, node, objs, nb_objs, CONNTRACK_NEXT_DNAT, get_next_index);
	return nb_objs;
}

static struct rte_node_register conntrack_node_base = {
	.name = "conntrack",
	.init = conntrack_node_init,
	.process = conntrack_node_process,

	.nb_edges = CONNTRACK_NEXT_MAX,
	.next_nodes = {
			[CONNTRACK_NEXT_LB] = "lb",
			[CONNTRACK_NEXT_DNAT] = "dnat",
			[CONNTRACK_NEXT_FIREWALL] = "firewall",
			[CONNTRACK_NEXT_DROP] = "drop",
		},
};

struct rte_node_register *conntrack_node_get(void)
{
	return &conntrack_node_base;
}

RTE_NODE_REGISTER(conntrack_node_base);
