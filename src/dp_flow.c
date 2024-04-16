// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#include "dp_flow.h"

#include <rte_icmp.h>

#include "dp_cntrack.h"
#include "dp_conf.h"
#include "dp_error.h"
#include "dp_log.h"
#include "dp_lpm.h"
#include "dp_nat.h"
#include "dp_vnf.h"
#include "dp_refcount.h"
#include "dp_mbuf_dyn.h"
#include "protocols/dp_icmpv6.h"
#include "rte_flow/dp_rte_flow.h"
#include "dp_timers.h"
#include "dp_error.h"

#include "rte_flow/dp_rte_flow_traffic_forward.h"

static struct rte_hash *ipv4_flow_tbl = NULL;
static bool offload_mode_enabled = 0;

int dp_flow_init(int socket_id)
{
	ipv4_flow_tbl = dp_create_jhash_table(DP_FLOW_TABLE_MAX, sizeof(struct flow_key),
										  "ipv4_flow_table", socket_id);
	if (!ipv4_flow_tbl)
		return DP_ERROR;

	offload_mode_enabled = dp_conf_is_offload_enabled();

	return DP_OK;
}

void dp_flow_free(void)
{
	dp_free_jhash_table(ipv4_flow_tbl);
}

static inline void dp_flow_log_key(const struct flow_key *key, const char *message)
{
	char src_ip[INET6_ADDRSTRLEN];
	char dst_ip[INET6_ADDRSTRLEN];

	DP_IPADDR_TO_STR(&key->l3_src, src_ip);
	DP_IPADDR_TO_STR(&key->l3_dst, dst_ip);

	DPS_LOG_DEBUG(message, _DP_LOG_UINT("flow_hash", dp_get_conntrack_flow_hash_value(key)),
		DP_LOG_PROTO(key->proto), DP_LOG_VNI(key->vni), DP_LOG_VNF_TYPE(key->vnf_type),
		DP_LOG_SRC_IPSTR(src_ip), DP_LOG_DST_IPSTR(dst_ip),
		DP_LOG_SRC_PORT(key->src.port_src), DP_LOG_DST_PORT(key->port_dst));
}

static __rte_always_inline int dp_build_icmp_flow_key(const struct dp_flow *df, struct flow_key *key /* out */, struct rte_mbuf *m /* in */)
{
	struct dp_icmp_err_ip_info icmp_err_ip_info = {0};

	if (df->l4_info.icmp_field.icmp_type == RTE_IP_ICMP_ECHO_REPLY || df->l4_info.icmp_field.icmp_type == RTE_IP_ICMP_ECHO_REQUEST) {
		key->port_dst = ntohs(df->l4_info.icmp_field.icmp_identifier);
		key->src.type_src = df->l4_info.icmp_field.icmp_type;
		return DP_OK;
	}

	if (df->l4_info.icmp_field.icmp_type == DP_IP_ICMP_TYPE_ERROR) {

		if (df->l4_info.icmp_field.icmp_code != DP_IP_ICMP_CODE_DST_PROTO_UNREACHABLE
			&& df->l4_info.icmp_field.icmp_code != DP_IP_ICMP_CODE_DST_PORT_UNREACHABLE
			&& df->l4_info.icmp_field.icmp_code != DP_IP_ICMP_CODE_FRAGMENT_NEEDED
		) {
			DPS_LOG_DEBUG("Received an ICMP error message with unsupported error code",
						   DP_LOG_VALUE(df->l4_info.icmp_field.icmp_code),
						   DP_LOG_SRC_IPV4(ntohl(df->src.src_addr)), DP_LOG_DST_IPV4(ntohl(df->dst.dst_addr)));
			return DP_ERROR;
		}

		dp_get_icmp_err_ip_hdr(m, &icmp_err_ip_info);

		if (!icmp_err_ip_info.err_ipv4_hdr || !icmp_err_ip_info.l4_src_port || !icmp_err_ip_info.l4_dst_port) {
			DPS_LOG_WARNING("Failed to extract attached ip header in icmp error message during icmp flow key building");
			return DP_ERROR;
		}

		// This is only called for ICMP, not for ICMPv6, so use IPv4 directly
		DP_SET_IPADDR4(key->l3_dst, ntohl(icmp_err_ip_info.err_ipv4_hdr->src_addr));
		DP_SET_IPADDR4(key->l3_src, ntohl(icmp_err_ip_info.err_ipv4_hdr->dst_addr));

		key->proto = icmp_err_ip_info.err_ipv4_hdr->next_proto_id;

		key->port_dst = ntohs(icmp_err_ip_info.l4_src_port);
		key->src.port_src = ntohs(icmp_err_ip_info.l4_dst_port);

		return DP_OK;
	}

	DPS_LOG_DEBUG("Received an ICMP error message with unsupported type",
				  DP_LOG_VALUE(df->l4_info.icmp_field.icmp_type),
				  DP_LOG_SRC_IPV4(ntohl(df->src.src_addr)), DP_LOG_DST_IPV4(ntohl(df->dst.dst_addr)));
	return DP_ERROR;
}

/* Isolating only VNF NAT conntrack entries at the moment. The others should follow */
static __rte_always_inline void dp_mark_vnf_type(struct dp_flow *df, const struct dp_port *port, struct flow_key *key)
{
	struct snat_data *s_data;

	if (port->is_pf) {
		if (df->vnf_type == DP_VNF_TYPE_NAT || df->vnf_type == DP_VNF_TYPE_LB_ALIAS_PFX)
			key->vnf_type = df->vnf_type;
		else
			key->vnf_type = DP_VNF_TYPE_UNDEFINED;
	} else if (key->l3_src.is_v6 && key->l3_dst.is_v6) {
		if (dp_is_ip6_in_nat64_range(key->l3_dst.ipv6))
			key->vnf_type = DP_VNF_TYPE_NAT;
	} else {
		s_data = dp_get_iface_snat_data(key->l3_src.ipv4, key->vni);
		if (s_data && s_data->nat_ip != 0)
			key->vnf_type = DP_VNF_TYPE_NAT;
		else if (dp_vnf_lbprefix_exists(port->port_id, key->vni, &key->l3_src, 32))
			key->vnf_type = DP_VNF_TYPE_LB_ALIAS_PFX;
		else
			key->vnf_type = DP_VNF_TYPE_UNDEFINED;
	}
}

int dp_build_flow_key(struct flow_key *key /* out */, struct rte_mbuf *m /* in */)
{
	struct dp_flow *df = dp_get_flow_ptr(m);
	const struct dp_port *port = dp_get_in_port(m);
	int ret = DP_OK;

	switch (df->l3_type) {
	case RTE_ETHER_TYPE_IPV4:
		DP_SET_IPADDR4(key->l3_dst, ntohl(df->dst.dst_addr));
		DP_SET_IPADDR4(key->l3_src, ntohl(df->src.src_addr));
		break;
	case RTE_ETHER_TYPE_IPV6:
		DP_SET_IPADDR6(key->l3_dst, df->dst.dst_addr6);
		DP_SET_IPADDR6(key->l3_src, df->src.src_addr6);
		break;
	default:
		return DP_ERROR;
	}

	key->proto = df->l4_type;

	if (port->is_pf)
		key->vni = df->tun_info.dst_vni;
	else
		key->vni = port->iface.vni;

	dp_mark_vnf_type(df, port, key);

	switch (df->l4_type) {
	case IPPROTO_TCP:
		key->port_dst = ntohs(df->l4_info.trans_port.dst_port);
		key->src.port_src = ntohs(df->l4_info.trans_port.src_port);
		break;
	case IPPROTO_UDP:
		key->port_dst = ntohs(df->l4_info.trans_port.dst_port);
		key->src.port_src = ntohs(df->l4_info.trans_port.src_port);
		break;
	case IPPROTO_ICMP:
		ret = dp_build_icmp_flow_key(df, key, m);
		break;
	case IPPROTO_ICMPV6:
		key->port_dst = ntohs(df->l4_info.icmp_field.icmp_identifier);
		key->src.type_src = df->l4_info.icmp_field.icmp_type;
		break;
	default:
		ret = DP_ERROR;
		break;
	}

	return ret;
}

void dp_invert_flow_key(const struct flow_key *key /* in */, struct flow_key *inv_key /* out */)
{
	dp_copy_ipaddr(&inv_key->l3_dst, &key->l3_src);
	dp_copy_ipaddr(&inv_key->l3_src, &key->l3_dst);
	inv_key->vni = key->vni;
	inv_key->vnf_type = key->vnf_type;
	inv_key->proto = key->proto;

	if ((key->proto == IPPROTO_TCP) || (key->proto == IPPROTO_UDP)) {
		inv_key->src.port_src = key->port_dst;
		inv_key->port_dst = key->src.port_src;
	} else if (key->proto == IPPROTO_ICMP) {
		inv_key->port_dst = key->port_dst;
		if (key->src.type_src == RTE_IP_ICMP_ECHO_REPLY)
			inv_key->src.type_src = RTE_IP_ICMP_ECHO_REQUEST;
		else if (key->src.type_src == RTE_IP_ICMP_ECHO_REQUEST)
			inv_key->src.type_src = RTE_IP_ICMP_ECHO_REPLY;
		else
			inv_key->src.type_src = 0;
	} else if (key->proto == IPPROTO_ICMPV6) {
		inv_key->port_dst = key->port_dst;
		if (key->src.type_src == DP_ICMPV6_ECHO_REPLY)
			inv_key->src.type_src = DP_ICMPV6_ECHO_REQUEST;
		else if (key->src.type_src == DP_ICMPV6_ECHO_REQUEST)
			inv_key->src.type_src = DP_ICMPV6_ECHO_REPLY;
		else
			inv_key->src.type_src = 0;
	} else {
		inv_key->port_dst = 0;
		inv_key->src.port_src = 0;
	}
}

static void dp_delete_flow_no_flush(const struct flow_key *key)
{
	int ret;

	ret = rte_hash_del_key(ipv4_flow_tbl, key);
	if (DP_FAILED(ret)) {
		if (ret == -ENOENT)
			dp_flow_log_key(key, "Attempt to delete a non-existing hash key");
		else
			DPS_LOG_ERR("Cannot delete key from flow table", DP_LOG_RET(ret));
		return;
	}
#ifdef ENABLE_PYTEST
	dp_flow_log_key(key, "Successfully deleted an existing hash key");
#endif
}

void dp_delete_flow(const struct flow_key *key)
{
	dp_delete_flow_no_flush(key);
	// removed a flow, purge the cache to be safe
	// (could only remove this key from cache, but that would need matching, which takes time)
	dp_cntrack_flush_cache();
}

int dp_add_flow(const struct flow_key *key, struct flow_value *flow_val)
{
	int ret = rte_hash_add_key_data(ipv4_flow_tbl, key, flow_val);

	if (DP_FAILED(ret)) {
		DPS_LOG_ERR("Cannot add data to flow table", DP_LOG_RET(ret));
		return ret;
	}
	return DP_OK;
}

int dp_get_flow(const struct flow_key *key, struct flow_value **p_flow_val)
{
	int ret = rte_hash_lookup_data(ipv4_flow_tbl, key, (void **)p_flow_val);

#ifdef ENABLE_PYTEST
	if (DP_FAILED(ret))
		dp_flow_log_key(key, "Cannot find data in flow table");
	else
		dp_flow_log_key(key, "Successfully found data in flow table");
#endif
	return ret;
}

void dp_free_flow(struct dp_ref *ref)
{
	struct flow_value *cntrack = container_of(ref, struct flow_value, ref_count);

	dp_free_network_nat_port(cntrack);
	dp_delete_flow_no_flush(&cntrack->flow_key[DP_FLOW_DIR_ORG]);
	dp_delete_flow_no_flush(&cntrack->flow_key[DP_FLOW_DIR_REPLY]);
	dp_cntrack_flush_cache();

	rte_free(cntrack);
}

void dp_free_network_nat_port(const struct flow_value *cntrack)
{
	int ret;

	if (cntrack->nf_info.nat_type == DP_FLOW_NAT_TYPE_NETWORK_LOCAL) {
		ret = dp_remove_network_snat_port(cntrack);
		if (DP_FAILED(ret))
			DPS_LOG_ERR("Failed to remove an allocated NAT port",
						DP_LOG_DST_IPV4(cntrack->flow_key[DP_FLOW_DIR_REPLY].l3_dst.ipv4),
						DP_LOG_DST_PORT(cntrack->flow_key[DP_FLOW_DIR_REPLY].port_dst),
						DP_LOG_RET(ret));
	}
}

int dp_destroy_rte_flow_agectx(struct flow_age_ctx *agectx)
{
	struct rte_flow_error error;
	int ret;

	if (!agectx)
		return DP_OK;

	if (agectx->handle) {
		ret = rte_flow_action_handle_destroy(agectx->port_id, agectx->handle, &error);
		if (DP_FAILED(ret))
			DPS_LOG_WARNING("Failed to remove an indirect action", DP_LOG_PORTID(agectx->port_id),
							DP_LOG_FLOW_ERROR(error.message), DP_LOG_RET(ret));
		agectx->handle =  NULL;
	}

	if (agectx->rte_flow) {
		ret = rte_flow_destroy(agectx->port_id, agectx->rte_flow, &error);
		if (DP_FAILED(ret))
			DPS_LOG_WARNING("Failed to destroy rte flow", DP_LOG_PORTID(agectx->port_id),
							DP_LOG_FLOW_ERROR(error.message), DP_LOG_RET(ret));
		agectx->rte_flow = NULL;
	}

	if (agectx->cntrack) {
		DPS_LOG_DEBUG("Removing rte flow from sw table",
					  DP_LOG_PORTID(agectx->port_id),
					  _DP_LOG_PTR("agectx_rteflow", agectx->rte_flow),
					  _DP_LOG_INT("flowval_ref_cnt", rte_atomic32_read(&(agectx->cntrack->ref_count.refcount))));

		ret = dp_del_rte_age_ctx(agectx->cntrack, agectx);
		if (DP_FAILED(ret))
			DPS_LOG_WARNING("Failed to remove agectx from conntrack object",
							DP_LOG_PORTID(agectx->port_id), DP_LOG_RET(ret));
		dp_ref_dec(&agectx->cntrack->ref_count);
	}

	rte_free(agectx);
	return DP_OK;
}

void dp_process_aged_flows(uint16_t port_id)
{
	int total, fetched;
	struct flow_age_ctx *agectx;
	struct rte_flow_error error;
	void **contexts;

	total = rte_flow_get_aged_flows(port_id, NULL, 0, &error);
	if (total <= 0)
		return;

	contexts = rte_zmalloc("aged_ctx", sizeof(void *) * total, RTE_CACHE_LINE_SIZE);
	if (contexts == NULL)
		return;

	fetched = rte_flow_get_aged_flows(port_id, contexts, total, &error);
	if (DP_FAILED(fetched)) {
		DPS_LOG_ERR("Getting aged flows failed", DP_LOG_RET(fetched));
		fetched = 0;
	} else if (fetched != total)
		DPS_LOG_WARNING("Not all aged flows received", DP_LOG_VALUE(fetched), DP_LOG_MAX(total));

	for (int i = 0; i < fetched; ++i) {
		agectx = (struct flow_age_ctx *)contexts[i];
		// return value ignored, aged flows are independent
		dp_destroy_rte_flow_agectx(agectx);
	}

	rte_free(contexts);
}

static void dp_rte_flow_remove(struct flow_value *flow_val)
{
	struct flow_age_ctx *agectx;

	for (size_t i = 0; i < RTE_DIM(flow_val->rte_age_ctxs); ++i) {
		agectx = flow_val->rte_age_ctxs[i];
		dp_destroy_rte_flow_agectx(agectx);
		// return value ignored as we are removing independent parts
	}
}

static __rte_always_inline int dp_rte_flow_query_and_remove(struct flow_value *flow_val)
{
	struct flow_age_ctx *curr_age_ctx;
	struct rte_flow_error error;
	struct rte_flow_query_age age_query;
	int ret;

	for (size_t i = 0; i < RTE_DIM(flow_val->rte_age_ctxs); ++i) {
		curr_age_ctx = flow_val->rte_age_ctxs[i];
		if (!curr_age_ctx || !curr_age_ctx->handle)
			continue;

		memset(&age_query, 0, sizeof(age_query));

		ret = rte_flow_action_handle_query(curr_age_ctx->port_id, curr_age_ctx->handle, &age_query, &error);
		if (DP_FAILED(ret)) {
			DPS_LOG_ERR("Failed to query tcp flow age action", DP_LOG_FLOW_ERROR(error.message), DP_LOG_RET(ret));
			return ret;
		}

		// delete this rule regardless if it has expired in hw or not (age_query.aged)
		if (age_query.sec_since_last_hit >= flow_val->timeout_value) {
			dp_destroy_rte_flow_agectx(curr_age_ctx);
			// return value ignored as we are removing independent parts
		}
	}
	return DP_OK;

}

static __rte_always_inline void dp_age_out_flow(struct flow_value *flow_val)
{
	flow_val->aged = 1;
	dp_ref_dec(&flow_val->ref_count);
}

void dp_process_aged_flows_non_offload(void)
{
	struct flow_value *flow_val = NULL;
	const struct flow_key *next_key;
	uint32_t iter = 0;
	uint64_t current_timestamp = rte_rdtsc();
	uint64_t timer_hz = rte_get_timer_hz();
	int	ret;

	while ((ret = rte_hash_iterate(ipv4_flow_tbl, (const void **)&next_key, (void **)&flow_val, &iter)) != -ENOENT) {
		if (DP_FAILED(ret)) {
			DPS_LOG_ERR("Iterating flow table failed while aging flows", DP_LOG_RET(ret));
			return;
		}
		// NOTE: possible optimization in moving a runtime constant 'timer_hz *' into 'timeout_value' directly
		// But it would require enlarging the flow_val member, thus this needs performance analysis first
		if (offload_mode_enabled && next_key->proto == IPPROTO_TCP) {
			ret = dp_rte_flow_query_and_remove(flow_val);
			if (DP_FAILED(ret))
				DPS_LOG_ERR("Failed to query and remove rte flows", DP_LOG_RET(ret));
		}

		if (unlikely((current_timestamp - flow_val->timestamp) > timer_hz * flow_val->timeout_value) && (!flow_val->aged))
			dp_age_out_flow(flow_val);
	}
}

static __rte_always_inline void dp_remove_flow(struct flow_value *flow_val)
{
	if (offload_mode_enabled)
		dp_rte_flow_remove(flow_val);
	dp_age_out_flow(flow_val);
}

void dp_remove_nat_flows(uint16_t port_id, enum dp_flow_nat_type nat_type)
{
	struct flow_value *flow_val = NULL;
	const void *next_key;
	uint32_t iter = 0;
	int ret;

	while ((ret = rte_hash_iterate(ipv4_flow_tbl, &next_key, (void **)&flow_val, &iter)) != -ENOENT) {
		if (DP_FAILED(ret)) {
			DPS_LOG_ERR("Iterating flow table failed while removing NAT flows", DP_LOG_RET(ret));
			return;
		}
		// NAT/VIP are in 1:1 relation to a VM (port_id), no need to check IP:port
		if (flow_val->created_port_id == port_id && flow_val->nf_info.nat_type == nat_type)
			dp_remove_flow(flow_val);
	}
}

void dp_remove_neighnat_flows(uint32_t ipv4, uint32_t vni, uint16_t min_port, uint16_t max_port)
{
	struct flow_value *flow_val = NULL;
	const struct flow_key *next_key;
	uint32_t iter = 0;
	int ret;

	while ((ret = rte_hash_iterate(ipv4_flow_tbl, (const void **)&next_key, (void **)&flow_val, &iter)) != -ENOENT) {
		if (DP_FAILED(ret)) {
			DPS_LOG_ERR("Iterating flow table failed while removing NAT flows", DP_LOG_RET(ret));
			return;
		}
		if (next_key->vni == vni && !next_key->l3_dst.is_v6 && next_key->l3_dst.ipv4 == ipv4
			&& next_key->port_dst >= min_port && next_key->port_dst < max_port
		) {
			dp_remove_flow(flow_val);
		}
	}
}

void dp_remove_iface_flows(uint16_t port_id, uint32_t ipv4, uint32_t vni)
{
	struct flow_value *flow_val = NULL;
	const struct flow_key *next_key;
	uint32_t iter = 0;
	int ret;

	while ((ret = rte_hash_iterate(ipv4_flow_tbl, (const void **)&next_key, (void **)&flow_val, &iter)) != -ENOENT) {
		if (DP_FAILED(ret)) {
			DPS_LOG_ERR("Iterating flow table failed while removing VM flows", DP_LOG_RET(ret));
			return;
		}
		if (flow_val->created_port_id == port_id
			|| (next_key->vni == vni && !flow_val->flow_key[DP_FLOW_DIR_ORG].l3_dst.is_v6 && flow_val->flow_key[DP_FLOW_DIR_ORG].l3_dst.ipv4 == ipv4)
		) {
			dp_remove_flow(flow_val);
		}
	}
}


hash_sig_t dp_get_conntrack_flow_hash_value(const struct flow_key *key)
{
	//It is not necessary to first test if this key exists, since for now, this function
	// is always called after either a flow is checked or added in the firewall node.
	return rte_hash_hash(ipv4_flow_tbl, key);
}

int dp_add_rte_age_ctx(struct flow_value *cntrack, struct flow_age_ctx *ctx)
{
	static_assert(RTE_DIM(cntrack->rte_age_ctxs) <= UINT8_MAX, "Conntrack age context storage is too large");
	for (size_t i = 0; i < RTE_DIM(cntrack->rte_age_ctxs); ++i) {
		if (!cntrack->rte_age_ctxs[i]) {
			cntrack->rte_age_ctxs[i] = ctx;
			ctx->ref_index_in_cntrack = (uint8_t)i;
			return DP_OK;
		}
	}
	DPS_LOG_ERR("Cannot add agectx to conntrack storage, at capacity", DP_LOG_MAX(sizeof(cntrack->rte_age_ctxs)));
	return DP_ERROR;
}

int dp_del_rte_age_ctx(struct flow_value *cntrack, const struct flow_age_ctx *ctx)
{
	if (ctx->ref_index_in_cntrack >= RTE_DIM(cntrack->rte_age_ctxs)) {
		DPS_LOG_ERR("Cannot delete agectx from conntrack storage, invalid index",
					DP_LOG_VALUE(ctx->ref_index_in_cntrack), DP_LOG_MAX(RTE_DIM(cntrack->rte_age_ctxs)));
		return DP_ERROR;
	}

	cntrack->rte_age_ctxs[ctx->ref_index_in_cntrack] = NULL;
	return DP_OK;
}
