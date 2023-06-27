#include <rte_common.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_mbuf.h>
#include "dp_error.h"
#include "dp_flow.h"
#include "dp_log.h"
#include "dp_lpm.h"
#include "dp_mbuf_dyn.h"
#include "dp_vnf.h"
#include "nodes/common_node.h"
#include "nodes/dhcp_node.h"
#include "rte_flow/dp_rte_flow.h"

static struct flow_key first_key = {0};
static struct flow_key second_key = {0};
static struct flow_key *prev_key, *curr_key;
static struct flow_value *prev_flow_val = NULL;
static int flow_timeout = DP_FLOW_DEFAULT_TIMEOUT;
static bool offload_mode_enabled = 0;

#define NEXT_NODES(NEXT) \
	NEXT(CONNTRACK_NEXT_LB, "lb") \
	NEXT(CONNTRACK_NEXT_DNAT, "dnat") \
	NEXT(CONNTRACK_NEXT_FIREWALL, "firewall")
DP_NODE_REGISTER(CONNTRACK, conntrack, NEXT_NODES);

static int conntrack_node_init(__rte_unused const struct rte_graph *graph, __rte_unused struct rte_node *node)
{
	prev_key = NULL;
	curr_key = &first_key;
	offload_mode_enabled = dp_conf_is_offload_enabled();
#ifdef ENABLE_PYTEST
	flow_timeout = dp_conf_get_flow_timeout();
#endif
	return DP_OK;
}

static __rte_always_inline void dp_cntrack_tcp_state(struct flow_value *flow_val, struct rte_tcp_hdr *tcp_hdr)
{
	uint8_t tcp_flags = tcp_hdr->tcp_flags;

	if (DP_TCP_PKT_FLAG_RST(tcp_flags)) {
		flow_val->l4_state.tcp_state = DP_FLOW_TCP_STATE_RST_FIN;
	} else if (DP_TCP_PKT_FLAG_FIN(tcp_flags)) {
		// this is not entirely 1:1 mapping to fin sequence,
		// but sufficient to determine if a tcp connection is almost successfuly closed
		// (last ack is still pending)
		if (flow_val->l4_state.tcp_state == DP_FLOW_TCP_STATE_ESTABLISHED)
			flow_val->l4_state.tcp_state = DP_FLOW_TCP_STATE_FINWAIT;
		else
			flow_val->l4_state.tcp_state = DP_FLOW_TCP_STATE_RST_FIN;
	} else {
		switch (flow_val->l4_state.tcp_state) {
		case DP_FLOW_TCP_STATE_NONE:
		case DP_FLOW_TCP_STATE_RST_FIN:
			if (DP_TCP_PKT_FLAG_SYN(tcp_flags))
				flow_val->l4_state.tcp_state = DP_FLOW_TCP_STATE_NEW_SYN;
			break;
		case DP_FLOW_TCP_STATE_NEW_SYN:
			if (DP_TCP_PKT_FLAG_SYNACK(tcp_flags))
				flow_val->l4_state.tcp_state = DP_FLOW_TCP_STATE_NEW_SYNACK;
			break;
		case DP_FLOW_TCP_STATE_NEW_SYNACK:
			if (DP_TCP_PKT_FLAG_ACK(tcp_flags))
				flow_val->l4_state.tcp_state = DP_FLOW_TCP_STATE_ESTABLISHED;
			break;
		default:
			// FIN-states already handled above
			break;
		}

	}
}

static __rte_always_inline void dp_cntrack_set_timeout_tcp_flow(struct flow_value *flow_val)
{

	if (flow_val->l4_state.tcp_state == DP_FLOW_TCP_STATE_ESTABLISHED) {
		flow_val->timeout_value = DP_FLOW_TCP_EXTENDED_TIMEOUT;

		if (offload_mode_enabled) {
			flow_val->offload_flags.orig = DP_FLOW_OFFLOAD_INSTALL;
			flow_val->offload_flags.reply = DP_FLOW_OFFLOAD_INSTALL;
		}
	} else
		flow_val->timeout_value = flow_timeout;
}


static __rte_always_inline struct flow_value *flow_table_insert_entry(struct flow_key *key, struct dp_flow *df, struct rte_mbuf *m)
{
	struct flow_value *flow_val = NULL;

	flow_val = rte_zmalloc("flow_val", sizeof(struct flow_value), RTE_CACHE_LINE_SIZE);
	if (!flow_val)
		return flow_val;
	/* Add original direction to conntrack table */
	dp_add_flow(key);
	flow_val->flow_key[DP_FLOW_DIR_ORG] = *key;
	flow_val->flow_state = DP_FLOW_STATE_NEW;
	flow_val->flow_status = DP_FLOW_STATUS_NONE;
	flow_val->nat_info.nat_type = DP_FLOW_NAT_TYPE_NONE;
	flow_val->timeout_value = flow_timeout;
	flow_val->created_port_id = m->port;

	df->flags.dir = DP_FLOW_DIR_ORG;

	if (offload_mode_enabled && df->l4_type != IPPROTO_TCP) {
		flow_val->offload_flags.orig = DP_FLOW_OFFLOAD_INSTALL;
		flow_val->offload_flags.reply = DP_FLOW_OFFLOAD_INSTALL;
	} else {
		flow_val->offload_flags.orig = DP_FLOW_NON_OFFLOAD;
		flow_val->offload_flags.reply = DP_FLOW_NON_OFFLOAD;
	}

	if (df->l4_type == IPPROTO_TCP)
		flow_val->l4_state.tcp_state = DP_FLOW_TCP_STATE_NONE;

	dp_ref_init(&flow_val->ref_count, dp_free_flow);
	dp_add_flow_data(key, flow_val);

	// Only the original flow (outgoing)'s hash value is recorded
	// Implicit casting from hash_sig_t to uint32_t!
	df->dp_flow_hash = dp_get_conntrack_flow_hash_value(key);

	dp_invert_flow_key(key);
	flow_val->flow_key[DP_FLOW_DIR_REPLY] = *key;
	dp_add_flow(key);
	dp_add_flow_data(key, flow_val);
	return flow_val;
}

static __rte_always_inline void change_flow_state_dir(struct flow_key *key, struct flow_value *flow_val, struct dp_flow *df)
{

	if (flow_val->nat_info.nat_type == DP_FLOW_NAT_TYPE_NETWORK_NEIGH) {
		if (dp_are_flows_identical(key, &flow_val->flow_key[DP_FLOW_DIR_ORG])) {
			if (flow_val->flow_state == DP_FLOW_STATE_NEW)
				flow_val->flow_state = DP_FLOW_STATE_ESTABLISHED;

			df->flags.dir = DP_FLOW_DIR_ORG;
		}
	} else {
		if (dp_are_flows_identical(key, &flow_val->flow_key[DP_FLOW_DIR_REPLY])) {

			if (flow_val->offload_flags.reply == DP_FLOW_OFFLOAD_INSTALL
				&& (flow_val->flow_state == DP_FLOW_STATE_ESTABLISHED))
				flow_val->offload_flags.reply = DP_FLOW_OFFLOADED;

			if (flow_val->flow_state == DP_FLOW_STATE_NEW)
				flow_val->flow_state = DP_FLOW_STATE_ESTABLISHED;

			df->flags.dir = DP_FLOW_DIR_REPLY;
		}

		if (dp_are_flows_identical(key, &flow_val->flow_key[DP_FLOW_DIR_ORG])) {

			if (flow_val->offload_flags.orig == DP_FLOW_OFFLOAD_INSTALL)
				flow_val->offload_flags.orig = DP_FLOW_OFFLOADED;

			// UDP traffic could be only one direction, thus from the second UDP packet in the same direction,
			// one UDP flow cannot be treated as a new one, otherwise it will always trigger the operations in snat or dnat
			// for new flows.
			if (df->l4_type == IPPROTO_UDP && flow_val->flow_state == DP_FLOW_STATE_NEW)
				flow_val->flow_state = DP_FLOW_STATE_ESTABLISHED;

			df->flags.dir = DP_FLOW_DIR_ORG;
		}
	}
	df->dp_flow_hash = dp_get_conntrack_flow_hash_value(key);

}

static __rte_always_inline bool dp_test_next_n_bytes_identical(const unsigned char *first_val, const unsigned char *second_val, uint8_t nr_bytes)
{

	for (uint8_t i = 0; i < nr_bytes; i++) {
		if ((first_val[i] ^ second_val[i]) > 0)
			return false;
	}

	return true;
}

static __rte_always_inline rte_edge_t dp_find_nxt_graph_node(struct dp_flow *df)
{
	if (df->flags.flow_type == DP_FLOW_TYPE_INCOMING) {
		switch (df->vnf_type) {
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
	struct rte_tcp_hdr *tcp_hdr;
	struct dp_flow *df;
	struct flow_key *key;
	bool key_cmp_result;
	int ret;

	df = dp_get_flow_ptr(m);
	ipv4_hdr = dp_get_ipv4_hdr(m);

	if (extract_inner_l3_header(m, ipv4_hdr, 0) < 0)
		return CONNTRACK_NEXT_DROP;

	if (extract_inner_l4_header(m, ipv4_hdr + 1, 0) < 0)
		return CONNTRACK_NEXT_DROP;

	if (df->l4_type == DP_IP_PROTO_UDP && ntohs(df->l4_info.trans_port.dst_port) == DP_BOOTP_SRV_PORT)
		return CONNTRACK_NEXT_DNAT;

	if (!dp_conf_is_conntrack_enabled())
		return CONNTRACK_NEXT_DNAT;

	if (df->l4_type == IPPROTO_TCP
		|| df->l4_type == IPPROTO_UDP
		|| df->l4_type == IPPROTO_ICMP
	) {
		key = curr_key;

		memset(key, 0, sizeof(struct flow_key));
		if (unlikely(DP_FAILED(dp_build_flow_key(key, m))))
			return CONNTRACK_NEXT_DROP;

		if (prev_key)
			key_cmp_result = dp_test_next_n_bytes_identical((const unsigned char *)prev_key,
													(const unsigned char *)curr_key,
													sizeof(struct flow_key));
		if (!prev_key || !key_cmp_result) {
			ret = dp_get_flow_data(key, (void **)&flow_val);
			if (unlikely(DP_FAILED(ret))) {
				if (likely(ret == -ENOENT)) {
					flow_val = flow_table_insert_entry(key, df, m);
					if (unlikely(!flow_val)) {
						DPNODE_LOG_WARNING(node, "Failed to allocate a new flow table entry");
						return CONNTRACK_NEXT_DROP;
					}
				} else {
					DPNODE_LOG_WARNING(node, "Flow table key search failed", DP_LOG_RET(ret));
					return CONNTRACK_NEXT_DROP;
				}
			} else {
				change_flow_state_dir(key, flow_val, df);
			}
			prev_key = curr_key;
			if (curr_key == &first_key)
				curr_key = &second_key;
			else
				curr_key = &first_key;

			prev_flow_val = flow_val;
		} else {
			flow_val = prev_flow_val;
			change_flow_state_dir(key, flow_val, df);
		}

		flow_val->timestamp = rte_rdtsc();

		if (df->l4_type == IPPROTO_TCP) {
			tcp_hdr = (struct rte_tcp_hdr *) (ipv4_hdr + 1);
			dp_cntrack_tcp_state(flow_val, tcp_hdr);
			dp_cntrack_set_timeout_tcp_flow(flow_val);
		}
		df->conntrack = flow_val;
	} else {
		return CONNTRACK_NEXT_DROP;
	}

	return dp_find_nxt_graph_node(df);
}

static uint16_t conntrack_node_process(struct rte_graph *graph,
									   struct rte_node *node,
									   void **objs,
									   uint16_t nb_objs)
{
	dp_foreach_graph_packet(graph, node, objs, nb_objs, CONNTRACK_NEXT_DNAT, get_next_index);
	return nb_objs;
}
