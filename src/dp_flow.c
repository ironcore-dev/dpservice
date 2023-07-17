#include "dp_flow.h"

#include <rte_icmp.h>

#include "dp_error.h"
#include "dp_log.h"
#include "dp_lpm.h"
#include "dp_nat.h"
#include "dp_vnf.h"
#include "dp_refcount.h"
#include "dp_mbuf_dyn.h"
#include "rte_flow/dp_rte_flow.h"
#include "dp_timers.h"
#include "dp_error.h"

#include "rte_flow/dp_rte_flow_traffic_forward.h"

// TODO(Tao?): this debug logging should be removed once the code stabilizes as it does happen quite often in the critical path
// As this is really specific to this module **and** is calling a function,
// this is a locally-defined macro for now (macro to preserve call-stack in logging)
#define DP_LOG_FLOW_KEY(KEY) \
	_DP_LOG_UINT("flow_hash", dp_get_conntrack_flow_hash_value(KEY)), \
	DP_LOG_PROTO((KEY)->proto), \
	DP_LOG_SRC_IPV4((KEY)->ip_src), DP_LOG_DST_IPV4((KEY)->ip_dst), \
	DP_LOG_SRC_PORT((KEY)->src.port_src), DP_LOG_DST_PORT((KEY)->port_dst)

static struct rte_hash *ipv4_flow_tbl = NULL;
static bool offload_mode_enabled = 0;

int dp_flow_init(int socket_id)
{
	ipv4_flow_tbl = dp_create_jhash_table(FLOW_MAX, sizeof(struct flow_key),
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

static int dp_build_icmp_flow_key(struct dp_flow *df, struct flow_key *key /* out */, struct rte_mbuf *m /* in */)
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

		key->ip_dst = ntohl(icmp_err_ip_info.err_ipv4_hdr->src_addr);
		key->ip_src = ntohl(icmp_err_ip_info.err_ipv4_hdr->dst_addr);

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


static __rte_always_inline int dp_get_vnf_entry(struct dp_vnf_value *val, enum vnf_type v_type, uint16_t portid)
{
	val->v_type = v_type;
	val->portid = portid;
	val->vni = dp_get_vm_vni(portid);
	return dp_find_vnf_with_value(val);
}

/* Isolating only VNF NAT conntrack entries at the moment. The others should follow */
static __rte_always_inline void dp_mark_vnf_type(struct dp_flow *df, struct flow_key *key, uint16_t port)
{
	struct snat_data *s_data;
	struct dp_vnf_value vnf_val;

	if (df->flags.flow_type == DP_FLOW_TYPE_INCOMING) {
		if (df->vnf_type == DP_VNF_TYPE_NAT || df->vnf_type == DP_VNF_TYPE_LB_ALIAS_PFX)
			key->vnf = (uint8_t)df->vnf_type;
		else
			key->vnf = (uint8_t)DP_VNF_TYPE_UNDEFINED;
	} else {
		vnf_val.alias_pfx.ip = key->ip_src;
		vnf_val.alias_pfx.length = 32;
		s_data = dp_get_vm_snat_data(key->ip_src, key->vni);
		if (s_data && s_data->network_nat_ip != 0) {
			key->vnf = (uint8_t)DP_VNF_TYPE_NAT;
		} else if (!DP_FAILED(dp_get_vnf_entry(&vnf_val, DP_VNF_TYPE_LB_ALIAS_PFX, port))){
			key->vnf = (uint8_t)DP_VNF_TYPE_LB_ALIAS_PFX;
		} else {
			key->vnf = (uint8_t)DP_VNF_TYPE_UNDEFINED;
		}
	}
}

int dp_build_flow_key(struct flow_key *key /* out */, struct rte_mbuf *m /* in */)
{
	struct dp_flow *df = dp_get_flow_ptr(m);
	int ret = DP_OK;

	key->ip_dst = ntohl(df->dst.dst_addr);
	key->ip_src = ntohl(df->src.src_addr);

	key->proto = df->l4_type;

	if (df->flags.flow_type == DP_FLOW_TYPE_INCOMING)
		key->vni = df->tun_info.dst_vni;
	else
		key->vni = dp_get_vm_vni(m->port);

	dp_mark_vnf_type(df, key, m->port);

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
	default:
		key->port_dst = 0;
		key->src.port_src = 0;
		break;
	}

	return ret;
}

void dp_invert_flow_key(struct flow_key *key /* in */, struct flow_key *inv_key /* out */)
{

	inv_key->ip_src = key->ip_dst;
	inv_key->ip_dst = key->ip_src;

	inv_key->vni = key->vni;
	inv_key->vnf = key->vnf;

	inv_key->proto = key->proto;

	if ((key->proto == IPPROTO_TCP) || (key->proto == IPPROTO_UDP)) {
		inv_key->src.port_src = key->port_dst;
		inv_key->port_dst = key->src.port_src;
	} else if (key->proto == IPPROTO_ICMP) {
		if (key->src.type_src == RTE_IP_ICMP_ECHO_REPLY)
			inv_key->src.type_src = RTE_IP_ICMP_ECHO_REQUEST;
		if (key->src.type_src == RTE_IP_ICMP_ECHO_REQUEST)
			inv_key->src.type_src = RTE_IP_ICMP_ECHO_REPLY;
	}
}

int dp_add_flow(struct flow_key *key)
{
	int ret = rte_hash_add_key(ipv4_flow_tbl, key);

	if (DP_FAILED(ret)) {
		DPS_LOG_ERR("Cannot add key to flow table", DP_LOG_RET(ret));
		return ret;
	}

	DPS_LOG_DEBUG("Successfully added a hash key", DP_LOG_FLOW_KEY(key));
	return DP_OK;
}

void dp_delete_flow_key(struct flow_key *key)
{
	int ret = rte_hash_del_key(ipv4_flow_tbl, key);
	
	if (DP_FAILED(ret)) {
		if (ret == -ENOENT)
			DPS_LOG_DEBUG("Attempt to delete a non-existing hash key", DP_LOG_FLOW_KEY(key));
		else
			DPS_LOG_ERR("Cannot delete key from flow table", DP_LOG_RET(ret));
		return;
	}

	DPS_LOG_DEBUG("Successfully deleted an existing hash key", DP_LOG_FLOW_KEY(key));
}

int dp_add_flow_data(struct flow_key *key, void *data)
{
	int ret = rte_hash_add_key_data(ipv4_flow_tbl, key, data);

	if (DP_FAILED(ret)) {
		DPS_LOG_ERR("Cannot add data to flow table", DP_LOG_RET(ret));
		return ret;
	}
	return DP_OK;
}

int dp_get_flow_data(struct flow_key *key, void **data)
{
	int result = rte_hash_lookup_data(ipv4_flow_tbl, key, data);

	if (DP_FAILED(result))
		*data = NULL;

	return result;
}

bool dp_are_flows_identical(struct flow_key *key1, struct flow_key *key2)
{
	return key1->proto == key2->proto
		&& key1->ip_src == key2->ip_src
		&& key1->ip_dst == key2->ip_dst
		&& key1->port_dst == key2->port_dst
		&& key1->src.port_src == key2->src.port_src
		&& key1->vni == key2->vni
		&& key1->vnf == key2->vnf;
}

void dp_free_flow(struct dp_ref *ref)
{
	struct flow_value *cntrack = container_of(ref, struct flow_value, ref_count);

	dp_free_network_nat_port(cntrack);
	dp_delete_flow_key(&cntrack->flow_key[DP_FLOW_DIR_ORG]);
	dp_delete_flow_key(&cntrack->flow_key[DP_FLOW_DIR_REPLY]);

	rte_free(cntrack);
}

void dp_free_network_nat_port(struct flow_value *cntrack)
{
	int ret;

	if (cntrack->nf_info.nat_type == DP_FLOW_NAT_TYPE_NETWORK_LOCAL) {
		ret = dp_remove_network_snat_port(cntrack);
		if (DP_FAILED(ret))
			DPS_LOG_ERR("Failed to remove an allocated NAT port",
						DP_LOG_DST_IPV4(cntrack->flow_key[DP_FLOW_DIR_REPLY].ip_dst),
						DP_LOG_DST_PORT(cntrack->flow_key[DP_FLOW_DIR_REPLY].port_dst),
						DP_LOG_RET(ret));
	}
}

int dp_destroy_rte_action_handle(uint16_t port_id, struct rte_flow_action_handle *handle, struct rte_flow_error *error)
{
	int ret;

	memset(error, 0, sizeof(struct rte_flow_error));
	error->message = "(no stated reason)";

	ret = rte_flow_action_handle_destroy(port_id, handle, error);
	if (DP_FAILED(ret))
		DPS_LOG_WARNING("Failed to destroy flow action handle",
						DP_LOG_FLOW_ERROR(error->message), DP_LOG_RET(ret));
	return ret;
}

void dp_process_aged_flows(int port_id)
{
	int nb_context, total = 0, idx;
	struct flow_age_ctx *agectx = NULL;
	struct rte_flow_error error;
	void **contexts;
	int ret;

	total = rte_flow_get_aged_flows(port_id, NULL, 0, &error);
	if (total <= 0)
		return;

	contexts = rte_zmalloc("aged_ctx", sizeof(void *) * total, RTE_CACHE_LINE_SIZE);
	if (contexts == NULL)
		return;

	nb_context = rte_flow_get_aged_flows(port_id, contexts, total, &error);
	if (nb_context != total)
		goto free;

	for (idx = 0; idx < nb_context; idx++) {
		agectx = (struct flow_age_ctx *)contexts[idx];
		if (!agectx)
			continue;

		if (agectx->handle) {
			ret = dp_destroy_rte_action_handle(port_id, agectx->handle, &error);
			if (DP_FAILED(ret))
				DPS_LOG_ERR("Failed to remove an indirect action", DP_LOG_PORTID(port_id), DP_LOG_RET(ret));
			agectx->handle = NULL;
		}

		if (agectx->rte_flow) {

			rte_flow_destroy(port_id, agectx->rte_flow, &error);

			DPS_LOG_DEBUG("Removed an aged rte flow due to timeout",
						  DP_LOG_PORTID(port_id),
						  _DP_LOG_PTR("agectx_rteflow", agectx->rte_flow),
						  _DP_LOG_INT("flowval_ref_cnt", rte_atomic32_read(&(agectx->cntrack->ref_count.refcount))));
			agectx->rte_flow = NULL;
			ret = dp_del_rte_age_ctx(agectx->cntrack, agectx);
			if (DP_FAILED(ret))
				DPS_LOG_ERR("Failed to remove agectx from conntrack object", DP_LOG_RET(ret));

			dp_ref_dec(&agectx->cntrack->ref_count);

			rte_free(agectx);
		}
	}

free:
	rte_free(contexts);
}

static __rte_always_inline int dp_rte_flow_query_and_remove(const struct flow_key *flow_key, struct flow_value *flow_val)
{
	uint8_t age_ctx_index;
	struct flow_age_ctx *curr_age_ctx;
	struct rte_flow_error error = {
		.message = "(no stated reason)",
	};
	struct rte_flow_query_age age_query;
	int ret;


	if (flow_key->proto == IPPROTO_TCP) {

		for (age_ctx_index = 0; age_ctx_index < DP_FLOW_VAL_MAX_AGE_STORE; age_ctx_index++) {
			curr_age_ctx = flow_val->rte_age_ctxs[age_ctx_index];
			if (curr_age_ctx && curr_age_ctx->handle) {

				memset(&error, 0, sizeof(error));
				memset(&age_query, 0, sizeof(age_query));

				ret = rte_flow_action_handle_query(curr_age_ctx->port_id, curr_age_ctx->handle, &age_query, &error);
				if (DP_FAILED(ret)) {
					DPS_LOG_ERR("Failed to query tcp flow age action", DP_LOG_FLOW_ERROR(error.message), DP_LOG_RET(ret));
					return ret;
				}

				// delete this rule regardless if it has expired in hw or not (age_query.aged)
				if (age_query.sec_since_last_hit >= flow_val->timeout_value) {

					ret = dp_destroy_rte_action_handle(curr_age_ctx->port_id, curr_age_ctx->handle, &error);
					if (DP_FAILED(ret)) {
						DPS_LOG_ERR("Failed to remove an indirect action", DP_LOG_PORTID(curr_age_ctx->port_id),
									DP_LOG_FLOW_ERROR(error.message), DP_LOG_RET(ret));
						return ret;
					}

					curr_age_ctx->handle =  NULL;
					DPS_LOG_DEBUG("Remove an aged rte flow from sw table via query",
								  DP_LOG_PORTID(curr_age_ctx->port_id),
								  _DP_LOG_PTR("agectx_rteflow", curr_age_ctx->rte_flow),
								  _DP_LOG_INT("flowval_ref_cnt", rte_atomic32_read(&(curr_age_ctx->cntrack->ref_count.refcount))));

					rte_flow_destroy(curr_age_ctx->port_id, curr_age_ctx->rte_flow, &error);
					curr_age_ctx->rte_flow = NULL;

					ret = dp_del_rte_age_ctx(flow_val, curr_age_ctx);
					if (DP_FAILED(ret)) {
						DPS_LOG_ERR("Failed to remove agectx from conntrack object", DP_LOG_RET(ret));
						return ret;
					}

					dp_ref_dec(&(flow_val->ref_count));

					rte_free(curr_age_ctx);
				}
			}
		}
	}
	return DP_OK;

}

void dp_process_aged_flows_non_offload(void)
{
	struct flow_value *flow_val = NULL;
	const void *next_key;
	uint32_t iter = 0;
	uint64_t current_timestamp = rte_rdtsc();
	uint64_t timer_hz = rte_get_timer_hz();
	int	ret;

	while (rte_hash_iterate(ipv4_flow_tbl, &next_key, (void **)&flow_val, &iter) >= 0) {
		// NOTE: possible optimization in moving a runtime constant 'timer_hz *' into 'timeout_value' directly
		// But it would require enlarging the flow_val member, thus this needs performance analysis first
		if (offload_mode_enabled) {
			ret = dp_rte_flow_query_and_remove((const struct flow_key *)next_key, flow_val);
			if (DP_FAILED(ret))
				DPS_LOG_ERR("Failed to query and remove rte flows", DP_LOG_RET(ret));
		}

		if (unlikely((current_timestamp - flow_val->timestamp) > timer_hz * flow_val->timeout_value) && (!flow_val->aged)) {
			flow_val->aged = 1;
			dp_ref_dec(&flow_val->ref_count);
		}
	}
}

hash_sig_t dp_get_conntrack_flow_hash_value(struct flow_key *key)
{
	//It is not necessary to first test if this key exists, since for now, this function
	// is always called after either a flow is checked or added in the firewall node.
	return rte_hash_hash(ipv4_flow_tbl, key);
}

int dp_add_rte_age_ctx(struct flow_value *cntrack, struct flow_age_ctx *ctx)
{
	uint8_t index;

	for (index = 0; index < DP_FLOW_VAL_MAX_AGE_STORE; index++) {
		if (!cntrack->rte_age_ctxs[index]) {
			cntrack->rte_age_ctxs[index] = ctx;
			ctx->ref_index_in_cntrack = index;
			break;
		}
	}

	if (index >= DP_FLOW_VAL_MAX_AGE_STORE) {
		DPS_LOG_ERR("Cannot add agectx to conntrack storage, at capacity",
					DP_LOG_VALUE(index), DP_LOG_MAX(DP_FLOW_VAL_MAX_AGE_STORE));
		return DP_ERROR;
	}

	return DP_OK;
}

int dp_del_rte_age_ctx(struct flow_value *cntrack, struct flow_age_ctx *ctx)
{
	if (ctx->ref_index_in_cntrack >= DP_FLOW_VAL_MAX_AGE_STORE) {
		DPS_LOG_ERR("Cannot delete agectx from conntrack storage, invalid index",
					DP_LOG_VALUE(ctx->ref_index_in_cntrack), DP_LOG_MAX(DP_FLOW_VAL_MAX_AGE_STORE));
		return DP_ERROR;
	}

	cntrack->rte_age_ctxs[ctx->ref_index_in_cntrack] = NULL;
	return DP_OK;
}

