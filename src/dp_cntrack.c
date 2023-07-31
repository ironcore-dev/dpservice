#include "dp_cntrack.h"
#include "dp_error.h"
#include "dp_flow.h"
#include "dp_log.h"
#include "dp_vnf.h"
#include "rte_flow/dp_rte_flow.h"


static struct flow_key first_key = {0};
static struct flow_key second_key = {0};
static struct flow_key *prev_key = NULL, *curr_key = &first_key;
static struct flow_value *prev_flow_val = NULL;
static int flow_timeout = DP_FLOW_DEFAULT_TIMEOUT;
static bool offload_mode_enabled = 0;

void dp_cntrack_init(void)
{
	offload_mode_enabled = dp_conf_is_offload_enabled();
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

static __rte_always_inline void dp_cntrack_init_flow_offload_flags(struct flow_value *flow_val, struct dp_flow *df)
{
	if (!offload_mode_enabled)
		return;

	if (df->l4_type != IPPROTO_TCP)
		flow_val->offload_flags.orig = DP_FLOW_OFFLOAD_INSTALL;
	else
		flow_val->offload_flags.orig = DP_FLOW_NON_OFFLOAD; // offload tcp traffic until it is established

	flow_val->offload_flags.reply = DP_FLOW_NON_OFFLOAD;
}


static __rte_always_inline void dp_cntrack_change_flow_offload_flags(struct flow_value *flow_val, struct dp_flow *df)
{
	if (!offload_mode_enabled)
		return;

	if (df->flags.dir == DP_FLOW_DIR_ORG) {

		if (flow_val->offload_flags.orig == DP_FLOW_NON_OFFLOAD)
			flow_val->offload_flags.orig = DP_FLOW_OFFLOAD_INSTALL;
		else if (flow_val->offload_flags.orig == DP_FLOW_OFFLOAD_INSTALL)
			flow_val->offload_flags.orig = DP_FLOW_OFFLOADED;
	} else if (df->flags.dir == DP_FLOW_DIR_REPLY) {

		if (flow_val->offload_flags.reply == DP_FLOW_NON_OFFLOAD)
			flow_val->offload_flags.reply = DP_FLOW_OFFLOAD_INSTALL;
		else if (flow_val->offload_flags.reply == DP_FLOW_OFFLOAD_INSTALL)
			flow_val->offload_flags.reply = DP_FLOW_OFFLOADED;
	}
}

static __rte_always_inline void dp_cntrack_set_timeout_tcp_flow(struct flow_value *flow_val, struct dp_flow *df)
{

	if (flow_val->l4_state.tcp_state == DP_FLOW_TCP_STATE_ESTABLISHED) {
		flow_val->timeout_value = DP_FLOW_TCP_EXTENDED_TIMEOUT;
		dp_cntrack_change_flow_offload_flags(flow_val, df);
	} else if (flow_val->l4_state.tcp_state == DP_FLOW_TCP_STATE_FINWAIT
			|| flow_val->l4_state.tcp_state == DP_FLOW_TCP_STATE_RST_FIN) {
		dp_cntrack_change_flow_offload_flags(flow_val, df);
		flow_val->timeout_value = flow_timeout;
	} else
		flow_val->timeout_value = flow_timeout;
}

static __rte_always_inline void dp_cntrack_set_pkt_offload_decision(struct dp_flow *df)
{
	if (df->flags.dir == DP_FLOW_DIR_ORG)
		df->flags.offload_decision = df->conntrack->offload_flags.orig;
	else
		df->flags.offload_decision = df->conntrack->offload_flags.reply;
}

static __rte_always_inline struct flow_value *flow_table_insert_entry(struct flow_key *key, struct dp_flow *df, struct rte_mbuf *m)
{
	struct flow_value *flow_val = NULL;
	struct flow_key inverted_key = {0};
	struct dp_vnf_value vnf_val;

	flow_val = rte_zmalloc("flow_val", sizeof(struct flow_value), RTE_CACHE_LINE_SIZE);
	if (!flow_val)
		return flow_val;

	vnf_val.alias_pfx.ip = key->ip_dst;
	vnf_val.alias_pfx.length = 32;
	/* Add original direction to conntrack table */
	dp_add_flow(key);
	flow_val->flow_key[DP_FLOW_DIR_ORG] = *key;
	flow_val->flow_status = DP_FLOW_STATUS_FLAG_NONE;
	/* Target ip of the traffic is an alias prefix of a VM in the same VNI on this dp-service */
	/* This will be an uni-directional traffic. So prepare the flag to offload immediately */
	if (offload_mode_enabled
		&& (df->flags.flow_type != DP_FLOW_TYPE_INCOMING)
		&& !DP_FAILED(dp_get_vnf_entry(&vnf_val, DP_VNF_TYPE_LB_ALIAS_PFX, m->port, DP_VNF_MATCH_ALL_PORT_ID))
	)
		flow_val->nf_info.nat_type = DP_FLOW_LB_TYPE_LOCAL_NEIGH_TRAFFIC;
	else
		flow_val->nf_info.nat_type = DP_FLOW_NAT_TYPE_NONE;

	flow_val->timeout_value = flow_timeout;
	flow_val->created_port_id = m->port;

	df->flags.dir = DP_FLOW_DIR_ORG;

	dp_cntrack_init_flow_offload_flags(flow_val, df);

	if (df->l4_type == IPPROTO_TCP)
		flow_val->l4_state.tcp_state = DP_FLOW_TCP_STATE_NONE;

	dp_ref_init(&flow_val->ref_count, dp_free_flow);
	dp_add_flow_data(key, flow_val);

	// Only the original flow (outgoing)'s hash value is recorded
	// Implicit casting from hash_sig_t to uint32_t!
	df->dp_flow_hash = dp_get_conntrack_flow_hash_value(key);

	dp_invert_flow_key(key, &inverted_key);
	flow_val->flow_key[DP_FLOW_DIR_REPLY] = inverted_key;
	dp_add_flow(&inverted_key);
	dp_add_flow_data(&inverted_key, flow_val);
	return flow_val;
}


static __rte_always_inline bool dp_test_next_n_bytes_identical(const unsigned char *first_val, const unsigned char *second_val, uint8_t nr_bytes)
{

	for (uint8_t i = 0; i < nr_bytes; i++) {
		if ((first_val[i] ^ second_val[i]) > 0)
			return false;
	}

	return true;
}

static __rte_always_inline void dp_set_pkt_flow_direction(struct flow_key *key, struct flow_value *flow_val, struct dp_flow *df)
{

	if (dp_are_flows_identical(key, &flow_val->flow_key[DP_FLOW_DIR_REPLY]))
		df->flags.dir = DP_FLOW_DIR_REPLY;

	if (dp_are_flows_identical(key, &flow_val->flow_key[DP_FLOW_DIR_ORG]))
		df->flags.dir = DP_FLOW_DIR_ORG;

	df->dp_flow_hash = dp_get_conntrack_flow_hash_value(key);
}

static __rte_always_inline void dp_set_flow_offload_flag(struct rte_mbuf *m, struct flow_value *flow_val, struct dp_flow *df)
{
	if (flow_val->nf_info.nat_type == DP_FLOW_NAT_TYPE_NETWORK_NEIGH
			|| flow_val->nf_info.nat_type == DP_FLOW_LB_TYPE_FORWARD
			|| flow_val->nf_info.nat_type == DP_FLOW_LB_TYPE_LOCAL_NEIGH_TRAFFIC) {
			dp_cntrack_change_flow_offload_flags(flow_val, df);
	} else {

		// recirc pkt shall not change flow's state because its ancestor has already done
		if (dp_get_pkt_mark(m)->flags.is_recirc)
			return;

		// when to offload reply pkt of a tcp flow is determined in dp_cntrack_set_timeout_tcp_flow
		if (df->l4_type != IPPROTO_TCP)
			dp_cntrack_change_flow_offload_flags(flow_val, df);
	}
}

int dp_cntrack_handle(struct rte_node *node, struct rte_mbuf *m, struct dp_flow *df)
{
	struct flow_value *flow_val = NULL;
	struct rte_ipv4_hdr *ipv4_hdr;
	struct rte_tcp_hdr *tcp_hdr;
	struct flow_key *key = NULL;
	bool same_key;
	int ret;

	#ifdef ENABLE_PYTEST
		flow_timeout = dp_conf_get_flow_timeout();
	#endif

	ipv4_hdr = dp_get_ipv4_hdr(m);

	key = curr_key;
	memset(key, 0, sizeof(struct flow_key));

	if (unlikely(DP_FAILED(dp_build_flow_key(key, m))))
		return DP_ERROR;

	same_key = prev_key && dp_test_next_n_bytes_identical((const unsigned char *)prev_key,
															  (const unsigned char *)curr_key,
															  sizeof(struct flow_key));

	if (!same_key) {
		ret = dp_get_flow_data(key, (void **)&flow_val);
		if (unlikely(DP_FAILED(ret))) {
			if (likely(ret == -ENOENT)) {
				flow_val = flow_table_insert_entry(key, df, m);
				if (unlikely(!flow_val)) {
					DPNODE_LOG_WARNING(node, "Failed to allocate a new flow table entry");
					return DP_ERROR;
				}
			} else {
				DPNODE_LOG_WARNING(node, "Flow table key search failed", DP_LOG_RET(ret));
				return DP_ERROR;
			}
		} else {
			dp_set_pkt_flow_direction(key, flow_val, df);
			dp_set_flow_offload_flag(m, flow_val, df);

		}
		prev_key = curr_key;
		if (curr_key == &first_key)
			curr_key = &second_key;
		else
			curr_key = &first_key;

		prev_flow_val = flow_val;
	} else {
		flow_val = prev_flow_val;
		dp_set_pkt_flow_direction(key, flow_val, df);
		dp_set_flow_offload_flag(m, flow_val, df);
	}

	flow_val->timestamp = rte_rdtsc();

	if (df->l4_type == IPPROTO_TCP && !dp_get_pkt_mark(m)->flags.is_recirc) {
		tcp_hdr = (struct rte_tcp_hdr *) (ipv4_hdr + 1);
		dp_cntrack_tcp_state(flow_val, tcp_hdr);
		dp_cntrack_set_timeout_tcp_flow(flow_val, df);
	}
	df->conntrack = flow_val;
	dp_cntrack_set_pkt_offload_decision(df);

	return DP_OK;
}
