// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#include "dp_cntrack.h"
#include "dp_conf.h"
#include "dp_error.h"
#include "dp_log.h"
#include "dp_port.h"
#include "dp_vnf.h"
#include "rte_flow/dp_rte_flow.h"
#include "rte_flow/dp_rte_flow_helpers.h"
#include "monitoring/dp_graphtrace.h"

static struct flow_key key_cache[2] = {0};
static int key_cache_index = 0;
static struct flow_key *prev_key = NULL;
static struct flow_key *curr_key = &key_cache[0];
static struct flow_value *cached_flow_val = NULL;

static int flow_timeout = DP_FLOW_DEFAULT_TIMEOUT;
static bool offload_mode_enabled = 0;

void dp_cntrack_init(void)
{
	offload_mode_enabled = dp_conf_is_offload_enabled();
#ifdef ENABLE_PYTEST
	flow_timeout = dp_conf_get_flow_timeout();
#endif
}

void dp_cntrack_flush_cache(void)
{
	prev_key = NULL;
	cached_flow_val = NULL;
}

static __rte_always_inline void dp_cache_flow_val(struct flow_value *flow_val)
{
	prev_key = curr_key;
	curr_key = &key_cache[++key_cache_index % RTE_DIM(key_cache)];
	cached_flow_val = flow_val;
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
		flow_val->offload_state.orig = DP_FLOW_OFFLOAD_INSTALL;
	else
		flow_val->offload_state.orig = DP_FLOW_NON_OFFLOAD; // offload tcp traffic until it is established

	flow_val->offload_state.reply = DP_FLOW_NON_OFFLOAD;
}


static __rte_always_inline void dp_cntrack_change_flow_offload_flags(struct rte_mbuf *m, struct flow_value *flow_val, struct dp_flow *df)
{
	bool offload_other_pf = false;
	struct dp_port *port = dp_get_in_port(m);

	if (!offload_mode_enabled)
		return;

	if (port->is_pf) {
		if (port == dp_get_pf0())
			offload_other_pf = !flow_val->incoming_flow_offloaded_flag.pf0;
		else
			offload_other_pf = !flow_val->incoming_flow_offloaded_flag.pf1;
	}

	if (df->flow_dir == DP_FLOW_DIR_ORG) {
		/* Despite the incoming flow is offloaded to one of the pf ports, pkts can arrive on another one */
		/* So we need to check if the incoming flow is offloaded on the current port, */
		/* if not, we do another offloading */
		if (flow_val->offload_state.orig == DP_FLOW_NON_OFFLOAD || offload_other_pf)
			flow_val->offload_state.orig = DP_FLOW_OFFLOAD_INSTALL;
		else if (flow_val->offload_state.orig == DP_FLOW_OFFLOAD_INSTALL)
			flow_val->offload_state.orig = DP_FLOW_OFFLOADED;

	} else if (df->flow_dir == DP_FLOW_DIR_REPLY) {
		if (flow_val->offload_state.reply == DP_FLOW_NON_OFFLOAD || offload_other_pf)
			flow_val->offload_state.reply = DP_FLOW_OFFLOAD_INSTALL;
		else if (flow_val->offload_state.reply == DP_FLOW_OFFLOAD_INSTALL)
			flow_val->offload_state.reply = DP_FLOW_OFFLOADED;
	}
}

static __rte_always_inline void dp_cntrack_set_timeout_tcp_flow(struct rte_mbuf *m, struct flow_value *flow_val, struct dp_flow *df)
{
	if (flow_val->l4_state.tcp_state == DP_FLOW_TCP_STATE_ESTABLISHED) {
		flow_val->timeout_value = DP_FLOW_TCP_EXTENDED_TIMEOUT;
		dp_cntrack_change_flow_offload_flags(m, flow_val, df);
	} else {
		flow_val->timeout_value = flow_timeout;
		if (flow_val->l4_state.tcp_state == DP_FLOW_TCP_STATE_FINWAIT
			|| flow_val->l4_state.tcp_state == DP_FLOW_TCP_STATE_RST_FIN)
			dp_cntrack_change_flow_offload_flags(m, flow_val, df);
	}
}

static __rte_always_inline void dp_cntrack_set_pkt_offload_decision(struct dp_flow *df)
{
	if (df->flow_dir == DP_FLOW_DIR_ORG)
		df->offload_state = df->conntrack->offload_state.orig;
	else
		df->offload_state = df->conntrack->offload_state.reply;
}

static __rte_always_inline struct flow_value *flow_table_insert_entry(struct flow_key *key, struct dp_flow *df, const struct dp_port *port)
{
	struct flow_value *flow_val;
	struct flow_key inverted_key;

	flow_val = rte_zmalloc("flow_val", sizeof(struct flow_value), RTE_CACHE_LINE_SIZE);
	if (!flow_val) {
		DPS_LOG_ERR("Failed to allocate new flow value");
		goto error_alloc;
	}

	flow_val->flow_key[DP_FLOW_DIR_ORG] = *key;
	flow_val->flow_flags = DP_FLOW_FLAG_NONE;
	flow_val->timeout_value = flow_timeout;
	flow_val->created_port_id = port->port_id;

	/* Target ip of the traffic is an alias prefix of a VM in the same VNI on this dp-service */
	/* This will be an uni-directional traffic, which does not expect its corresponding reverse traffic */
	/* Details can be found in https://github.com/ironcore-dev/dpservice/pull/341 */
	if (offload_mode_enabled
		&& !port->is_pf
		&& dp_vnf_lbprefix_exists(DP_VNF_MATCH_ALL_PORT_IDS, key->vni, key->l3_dst.ip4, 32)
	)
		flow_val->nf_info.nat_type = DP_FLOW_LB_TYPE_LOCAL_NEIGH_TRAFFIC;
	else
		flow_val->nf_info.nat_type = DP_FLOW_NAT_TYPE_NONE;

	df->flow_dir = DP_FLOW_DIR_ORG;

	dp_cntrack_init_flow_offload_flags(flow_val, df);

	if (df->l4_type == IPPROTO_TCP)
		flow_val->l4_state.tcp_state = DP_FLOW_TCP_STATE_NONE;

	dp_ref_init(&flow_val->ref_count, dp_free_flow);
	if (DP_FAILED(dp_add_flow(key, flow_val)))
		goto error_add;

	// Only the original flow (outgoing)'s hash value is recorded
	// Implicit casting from hash_sig_t to uint32_t!
	df->dp_flow_hash = dp_get_conntrack_flow_hash_value(key);

	memset(&inverted_key, 0, sizeof(inverted_key));
	dp_invert_flow_key(key, &inverted_key);
	flow_val->flow_key[DP_FLOW_DIR_REPLY] = inverted_key;
	if (DP_FAILED(dp_add_flow(&inverted_key, flow_val)))
		goto error_add_inv;

	return flow_val;

error_add_inv:
	dp_delete_flow(key);
error_add:
	rte_free(flow_val);
error_alloc:
	return NULL;
}


static __rte_always_inline void dp_set_pkt_flow_direction(struct flow_key *key, struct flow_value *flow_val, struct dp_flow *df)
{
	if (dp_are_flows_identical(key, &flow_val->flow_key[DP_FLOW_DIR_REPLY]))
		df->flow_dir = DP_FLOW_DIR_REPLY;

	if (dp_are_flows_identical(key, &flow_val->flow_key[DP_FLOW_DIR_ORG]))
		df->flow_dir = DP_FLOW_DIR_ORG;

	df->dp_flow_hash = dp_get_conntrack_flow_hash_value(key);
}

static __rte_always_inline void dp_set_flow_offload_flag(struct rte_mbuf *m, struct flow_value *flow_val, struct dp_flow *df)
{
	if (flow_val->nf_info.nat_type == DP_FLOW_NAT_TYPE_NETWORK_NEIGH
		|| flow_val->nf_info.nat_type == DP_FLOW_LB_TYPE_FORWARD
		|| flow_val->nf_info.nat_type == DP_FLOW_LB_TYPE_LOCAL_NEIGH_TRAFFIC
	) {
		dp_cntrack_change_flow_offload_flags(m, flow_val, df);
	} else {
		// after introducing vnf_type as part of the flow key, recirc pkt shall perform offload state changing
		// instead of its ancestor pkt. Its ancestor pkt's flow still resides as before, but its state is not changing
		if (df->vnf_type == DP_VNF_TYPE_LB)
			return;
		// when to offload reply pkt of a tcp flow is determined in dp_cntrack_set_timeout_tcp_flow
		if (df->l4_type != IPPROTO_TCP)
			dp_cntrack_change_flow_offload_flags(m, flow_val, df);
	}
}

static __rte_always_inline int dp_get_flow_val(struct rte_mbuf *m, struct dp_flow *df, struct flow_value **p_flow_val)
{
	int ret;

	// TODO(plague): discuss making DP_FAILED() unlikely by default
	ret = dp_build_flow_key(curr_key, m);
	if (unlikely(DP_FAILED(ret)))
		return ret;

	// highly optimized comparator for a specific key size
	static_assert(sizeof(struct flow_key) == 42, "struct flow_key changed size");
	if (prev_key
		&& ((const uint64_t *)curr_key)[0] == ((const uint64_t *)prev_key)[0]
		&& ((const uint64_t *)curr_key)[1] == ((const uint64_t *)prev_key)[1]
		&& ((const uint64_t *)curr_key)[2] == ((const uint64_t *)prev_key)[2]
		&& ((const uint64_t *)curr_key)[3] == ((const uint64_t *)prev_key)[3]
		&& ((const uint64_t *)curr_key)[4] == ((const uint64_t *)prev_key)[4]
		&& ((const uint16_t *)curr_key)[20] == ((const uint16_t *)prev_key)[20]
	) {
		// flow is the same as it was for the previous packet
		*p_flow_val = cached_flow_val;
		dp_set_pkt_flow_direction(curr_key, cached_flow_val, df);
		dp_set_flow_offload_flag(m, cached_flow_val, df);
		return DP_OK;
	}

	// cache miss, try the flow table
	ret = dp_get_flow(curr_key, p_flow_val);
	if (unlikely(DP_FAILED(ret))) {
		if (unlikely(ret != -ENOENT)) {
			DPS_LOG_WARNING("Flow table key search failed", DP_LOG_RET(ret));
			return ret;
		}
		// create new flow if needed
		*p_flow_val = flow_table_insert_entry(curr_key, df, dp_get_in_port(m));
		if (unlikely(!*p_flow_val)) {
			DPS_LOG_WARNING("Failed to create a new flow table entry");
			return DP_ERROR;
		}
		dp_cache_flow_val(*p_flow_val);
		return DP_OK;
	}

	// already established flow found
	dp_set_pkt_flow_direction(curr_key, *p_flow_val, df);
	dp_set_flow_offload_flag(m, *p_flow_val, df);
	dp_cache_flow_val(*p_flow_val);
	return DP_OK;
}

int dp_cntrack_handle(struct rte_mbuf *m, struct dp_flow *df)
{
	struct flow_value *flow_val;
	struct rte_tcp_hdr *tcp_hdr;
	int ret;

	ret = dp_get_flow_val(m, df, &flow_val);
	if (DP_FAILED(ret))
		return ret;

	flow_val->timestamp = rte_rdtsc();

	if (df->l4_type == IPPROTO_TCP && df->vnf_type != DP_VNF_TYPE_LB) {
		tcp_hdr = (struct rte_tcp_hdr *)(dp_get_ipv4_hdr(m) + 1);
		dp_cntrack_tcp_state(flow_val, tcp_hdr);
		dp_cntrack_set_timeout_tcp_flow(m, flow_val, df);
	}
	df->conntrack = flow_val;
	dp_cntrack_set_pkt_offload_decision(df);

	return DP_OK;
}
