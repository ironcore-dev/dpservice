#include "dp_flow.h"

#include <rte_icmp.h>

#include "dp_error.h"
#include "dp_log.h"
#include "dp_lpm.h"
#include "dp_nat.h"
#include "dp_refcount.h"
#include "node_api.h"
#include "rte_flow/dp_rte_flow.h"
#include "dp_timers.h"
#include "dp_error.h"

#include "rte_flow/dp_rte_flow_traffic_forward.h"

#define DP_FLOW_LOG_KEY(MSG, KEY) do { \
	if (rte_log_get_level(RTE_LOGTYPE_DPSERVICE) >= RTE_LOG_DEBUG) \
		dp_log_flow_key_info((MSG), (KEY)); \
} while (0)

static struct rte_hash *ipv4_flow_tbl = NULL;
static bool offload_mode_enabled = 0;

static void dp_log_flow_key_info(const char *msg, struct flow_key *key)
{
	uint32_t hash_value = dp_get_conntrack_flow_hash_value(key);
	const char *protocol;

	if (key->proto == IPPROTO_TCP)
		protocol = "tcp";
	else if (key->proto == IPPROTO_UDP)
		protocol = "udp";
	else if (key->proto == IPPROTO_ICMP)
		protocol = "icmp";
	else
		protocol = "unknown";

	DPS_LOG_DEBUG("%s: %u, %s, src_ip: " DP_IPV4_PRINT_FMT ", dst_ip: " DP_IPV4_PRINT_FMT ", src_port: %d, port_dst: %d",
		msg, hash_value, protocol,
		DP_IPV4_PRINT_BYTES(ntohl(key->ip_src)), DP_IPV4_PRINT_BYTES(ntohl(key->ip_dst)),
		key->src.port_src, key->port_dst);
}

int dp_flow_init(int socket_id)
{
	ipv4_flow_tbl = dp_create_jhash_table(FLOW_MAX, sizeof(struct flow_key),
										  "ipv4_flow_table", socket_id);
	if (!ipv4_flow_tbl)
		return DP_ERROR;

	offload_mode_enabled = dp_conf_is_offload_enabled();

	return DP_OK;
}

void dp_flow_free()
{
	dp_free_jhash_table(ipv4_flow_tbl);
}

static int dp_build_icmp_flow_key(struct dp_flow *df_ptr, struct flow_key *key /* out */, struct rte_mbuf *m /* in */)
{
	struct dp_icmp_err_ip_info icmp_err_ip_info = {0};

	if (df_ptr->l4_info.icmp_field.icmp_type == RTE_IP_ICMP_ECHO_REPLY || df_ptr->l4_info.icmp_field.icmp_type == RTE_IP_ICMP_ECHO_REQUEST) {
		key->port_dst = ntohs(df_ptr->l4_info.icmp_field.icmp_identifier);
		key->src.type_src = df_ptr->l4_info.icmp_field.icmp_type;
		return DP_OK;
	}

	if (df_ptr->l4_info.icmp_field.icmp_type == DP_IP_ICMP_TYPE_ERROR) {

		if (df_ptr->l4_info.icmp_field.icmp_code != DP_IP_ICMP_CODE_DST_PROTO_UNREACHABLE
			&& df_ptr->l4_info.icmp_field.icmp_code != DP_IP_ICMP_CODE_DST_PORT_UNREACHABLE
			&& df_ptr->l4_info.icmp_field.icmp_code != DP_IP_ICMP_CODE_FRAGMENT_NEEDED
		) {
			DPS_LOG_DEBUG("received an ICMP error message with unsupported error code %d, src_ip: " DP_IPV4_PRINT_FMT ", dst_ip: " DP_IPV4_PRINT_FMT,
						  df_ptr->l4_info.icmp_field.icmp_code,
						  DP_IPV4_PRINT_BYTES(df_ptr->src.src_addr), DP_IPV4_PRINT_BYTES(df_ptr->dst.dst_addr));
			return DP_ERROR;
		}

		dp_get_icmp_err_ip_hdr(m, &icmp_err_ip_info);

		if (!icmp_err_ip_info.err_ipv4_hdr || !icmp_err_ip_info.l4_src_port || !icmp_err_ip_info.l4_dst_port) {
			DPS_LOG_WARNING("failed to extract attached ip header in icmp error message during icmp flow key building");
			return DP_ERROR;
		}

		key->ip_dst = ntohl(icmp_err_ip_info.err_ipv4_hdr->src_addr);
		key->ip_src = ntohl(icmp_err_ip_info.err_ipv4_hdr->dst_addr);

		key->proto = icmp_err_ip_info.err_ipv4_hdr->next_proto_id;

		key->port_dst = ntohs(icmp_err_ip_info.l4_src_port);
		key->src.port_src = ntohs(icmp_err_ip_info.l4_dst_port);

		return DP_OK;
	}

	DPS_LOG_DEBUG("received an ICMP error message with unsupported type %d, src_ip: " DP_IPV4_PRINT_FMT ", dst_ip: " DP_IPV4_PRINT_FMT,
				  df_ptr->l4_info.icmp_field.icmp_type,
				  DP_IPV4_PRINT_BYTES(df_ptr->src.src_addr), DP_IPV4_PRINT_BYTES(df_ptr->dst.dst_addr));
	return DP_ERROR;
}

int dp_build_flow_key(struct flow_key *key /* out */, struct rte_mbuf *m /* in */)
{
	struct dp_flow *df_ptr = get_dp_flow_ptr(m);
	int ret = DP_OK;

	key->ip_dst = ntohl(df_ptr->dst.dst_addr);
	key->ip_src = ntohl(df_ptr->src.src_addr);

	key->proto = df_ptr->l4_type;

	if (df_ptr->flags.flow_type == DP_FLOW_TYPE_INCOMING)
		key->vni = df_ptr->tun_info.dst_vni;
	else
		key->vni = dp_get_vm_vni(m->port);

	switch (df_ptr->l4_type) {
	case IPPROTO_TCP:
		key->port_dst = ntohs(df_ptr->l4_info.trans_port.dst_port);
		key->src.port_src = ntohs(df_ptr->l4_info.trans_port.src_port);
		break;
	case IPPROTO_UDP:
		key->port_dst = ntohs(df_ptr->l4_info.trans_port.dst_port);
		key->src.port_src = ntohs(df_ptr->l4_info.trans_port.src_port);
		break;
	case IPPROTO_ICMP:
		ret = dp_build_icmp_flow_key(df_ptr, key, m);
		break;
	default:
		key->port_dst = 0;
		key->src.port_src = 0;
		break;
	}

	return ret;
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

int dp_add_flow(struct flow_key *key)
{
	int ret = rte_hash_add_key(ipv4_flow_tbl, key);

	if (DP_FAILED(ret)) {
		DPS_LOG_ERR("Cannot add key to flow table %s", dp_strerror(ret));
		return ret;
	}

	DP_FLOW_LOG_KEY("Successfully added a hash key", key);
	return DP_OK;
}

void dp_delete_flow_key(struct flow_key *key)
{
	int ret = rte_hash_del_key(ipv4_flow_tbl, key);
	
	if (DP_FAILED(ret)) {
		if (ret == -ENOENT)
			DP_FLOW_LOG_KEY("Attempt to delete a non-existing hash key", key);
		else
			DPS_LOG_ERR("Cannot delete key from flow table %s", dp_strerror(ret));
		return;
	}

	DP_FLOW_LOG_KEY("Successfully deleted an existing hash key", key);
}

int dp_add_flow_data(struct flow_key *key, void *data)
{
	int ret = rte_hash_add_key_data(ipv4_flow_tbl, key, data);

	if (DP_FAILED(ret)) {
		DPS_LOG_ERR("Cannot add data to flow table %s", dp_strerror(ret));
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
		&& key1->src.port_src == key2->src.port_src;
}

void dp_free_flow(struct dp_ref *ref)
{
	struct flow_value *cntrack = container_of(ref, struct flow_value, ref_count);

	dp_free_network_nat_port(cntrack);
	dp_delete_flow_key(&cntrack->flow_key[cntrack->dir]);
	dp_delete_flow_key(&cntrack->flow_key[!cntrack->dir]);

	rte_free(cntrack);
}

void dp_free_network_nat_port(struct flow_value *cntrack)
{
	int ret;

	if (cntrack->nat_info.nat_type == DP_FLOW_NAT_TYPE_NETWORK_LOCAL) {
		ret = dp_remove_network_snat_port(cntrack);
		if (DP_FAILED(ret))
			DPS_LOG_ERR("failed to remove an allocated network NAT port: " DP_IPV4_PRINT_FMT "::%d %s",
						DP_IPV4_PRINT_BYTES(htonl(cntrack->flow_key[DP_FLOW_DIR_REPLY].ip_dst)),
						cntrack->flow_key[DP_FLOW_DIR_REPLY].port_dst, dp_strerror(ret));
	}
}

int dp_destroy_rte_action_handle(uint16_t port_id, struct rte_flow_action_handle *handle, struct rte_flow_error *error)
{
	int ret;

	memset(error, 0, sizeof(struct rte_flow_error));
	ret = rte_flow_action_handle_destroy(port_id, handle, error);
	if (DP_FAILED(ret)) {
		DPS_LOG_WARNING("failed to destroy a flow action handle, error code:%d, reason %s", ret,
								error->message ? error->message : "(no stated reason)");
		return DP_ERROR;
	}
	return DP_OK;
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

		if (agectx->handle) {

			if (DP_FAILED(dp_destroy_rte_action_handle(port_id, agectx->handle, &error)))
				DPS_LOG_ERR("failed to remove a indirect action from port %d", port_id);

			agectx->handle = NULL;

		}

		if (agectx->rte_flow) {

			rte_flow_destroy(port_id, agectx->rte_flow, &error);

			DPS_LOG_DEBUG("Removed an aged rte flow due to timeout, agectx: rteflow %p\n flowval: flow_ref_cnt %d  rte_flow inserted on port %d \n",
									(void *)agectx->rte_flow, rte_atomic32_read(&(agectx->cntrack->ref_count.refcount)), port_id);
			agectx->rte_flow = NULL;
			ret = dp_del_rte_age_ctx(agectx->cntrack, agectx);
			if (DP_FAILED(ret))
				DPS_LOG_ERR("failed to remove age ctx from its associated cntrack obj");

			dp_ref_dec(&agectx->cntrack->ref_count);

			rte_free(agectx);
		}
	}

free:
	rte_free(contexts);
}

static __rte_always_inline int dp_rte_flow_query_and_remove(struct flow_key *flow_key, struct flow_value *flow_val)
{
	uint8_t age_ctx_index;
	struct flow_age_ctx *curr_age_ctx;
	struct rte_flow_error error;
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
					DPS_LOG_ERR("failed to query tcp flow's age action due to code: %d, with error msg: %s", ret,
									error.message ? error.message : "(no stated reason)");
					return DP_ERROR;
				}

				// delete this rule regardless if it has expired in hw or not (age_query.aged)
				if (age_query.sec_since_last_hit >= flow_val->timeout_value) {

					if (DP_FAILED(dp_destroy_rte_action_handle(curr_age_ctx->port_id, curr_age_ctx->handle, &error))) {
						DPS_LOG_ERR("failed to remove a indirect action from port %d", curr_age_ctx->port_id);
						return DP_ERROR;
					}

					curr_age_ctx->handle =  NULL;
					DPS_LOG_DEBUG("Remove an aged rte flow from sw table via query \n				\
									gectx: rteflow %p\n flowval: flow_ref_cnt %d  rte_flow inserted on port %d \n",
									(void *)curr_age_ctx->rte_flow, rte_atomic32_read(&(curr_age_ctx->cntrack->ref_count.refcount)),
									curr_age_ctx->port_id);

					rte_flow_destroy(curr_age_ctx->port_id, curr_age_ctx->rte_flow, &error);
					curr_age_ctx->rte_flow = NULL;

					ret = dp_del_rte_age_ctx(flow_val, curr_age_ctx);
					if (DP_FAILED(ret)) {
						DPS_LOG_ERR("failed to remove age ctx from its associated cntrack obj");
						return DP_ERROR;
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
			ret = dp_rte_flow_query_and_remove((struct flow_key *)next_key, flow_val);
			if (DP_FAILED(ret))
				DPS_LOG_ERR("failed to query and remove rte flows");
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
		DPS_LOG_ERR("try to add age ctx to cntrack storage but exceed its capacity");
		return DP_ERROR;
	}

	return DP_OK;
}

int dp_del_rte_age_ctx(struct flow_value *cntrack, struct flow_age_ctx *ctx)
{
	if (ctx->ref_index_in_cntrack >= DP_FLOW_VAL_MAX_AGE_STORE) {
		DPS_LOG_ERR("try to delete age ctx from cntrack storage but it is not a valid index");
		return DP_ERROR;
	}

	cntrack->rte_age_ctxs[ctx->ref_index_in_cntrack] = NULL;
	return DP_OK;
}

