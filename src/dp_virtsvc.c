// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#include "dp_virtsvc.h"

#include <stdlib.h>
#include <rte_cycles.h>
#include <rte_flow.h>
#include <rte_malloc.h>

#include "dp_conf.h"
#include "dp_error.h"
#include "dp_flow.h"
#include "dp_log.h"
#include "dp_multi_path.h"
#include "dp_util.h"
#include "rte_flow/dp_rte_flow_init.h"
#include "rte_flow/dp_rte_async_flow.h"
#include "rte_flow/dp_rte_async_flow_isolation.h"
#include "rte_flow/dp_rte_flow_helpers.h"

// WARNING: This module is not designed to be thread-safe (even though it could work)
// It is assumed that thread-unsafe code will only ever be called from one node
// and that such node will only be bound to one thread.

#define DP_VIRTSVC_TELEMETRY_MAX_NAME_SIZE sizeof("TCP:255.255.255.255:65535")

// Due to the specificity (and accessing the struct)
// Local-only definition
#define DP_LOG_VIRTSVC(SERVICE) \
	_DP_LOG_IPV4("virtsvc_address", ntohl((SERVICE)->virtual_addr)), \
	_DP_LOG_IPV6("service_address", (SERVICE)->service_addr), \
	_DP_LOG_UINT("virtsvc_port", ntohs((SERVICE)->virtual_port)), \
	_DP_LOG_UINT("service_port", ntohs((SERVICE)->service_port)), \
	DP_LOG_PROTO((SERVICE)->proto)

// packed, because hashing would include padding otherwise
struct dp_virtsvc_conn_key {
	uint16_t vf_port_id;
	rte_be16_t vf_l4_port;
	rte_be32_t vf_ip;
} __rte_packed;

static struct dp_virtsvc *dp_virtservices;
static struct dp_virtsvc *dp_virtservices_end;

#define DP_FOREACH_VIRTSVC(SERVICES, VARNAME) \
	for (struct dp_virtsvc *VARNAME = dp_virtservices; \
		 (VARNAME) < dp_virtservices_end; \
		 ++VARNAME)

static uint64_t port_timeout = DP_FLOW_DEFAULT_TIMEOUT;
static uint64_t established_port_timeout = DP_FLOW_TCP_EXTENDED_TIMEOUT;
#ifdef ENABLE_PYTEST
static bool fast_timeout = false;
#endif

// TODO temporary definition I think
struct dp_port_rte_async_templates {
	struct rte_flow_pattern_template *pattern_templates[1];
	struct rte_flow_actions_template *action_templates[1];
	struct rte_flow_template_table *template_tables[1];
};
static struct dp_port_rte_async_templates virtsvc_async_templates[DP_MAX_PF_PORTS];

static struct dp_virtsvc_lookup_entry *dp_virtsvc_ipv4_tree = NULL;
static struct dp_virtsvc_lookup_entry *dp_virtsvc_ipv6_tree = NULL;

const struct dp_virtsvc_lookup_entry *dp_virtsvc_get_ipv4_tree(void)
{
	return dp_virtsvc_ipv4_tree;
}

const struct dp_virtsvc_lookup_entry *dp_virtsvc_get_ipv6_tree(void)
{
	return dp_virtsvc_ipv6_tree;
}

static int dp_virtsvc_array_to_tree(struct dp_virtsvc_lookup_entry **dst, struct dp_virtsvc **array, int start, int end)
{
	struct dp_virtsvc_lookup_entry *entry;
	int mid;

	*dst = NULL;

	if (start > end)
		return DP_OK;

	entry = (struct dp_virtsvc_lookup_entry *)malloc(sizeof(struct dp_virtsvc_lookup_entry));
	if (!entry)
		return DP_ERROR;

	mid = (start + end) / 2;
	entry->virtsvc = array[mid];

	if (DP_FAILED(dp_virtsvc_array_to_tree(&entry->left, array, start, mid-1))
		|| DP_FAILED(dp_virtsvc_array_to_tree(&entry->right, array, mid+1, end)))
		return DP_ERROR;

	*dst = entry;
	return DP_OK;
}

static int dp_virtsvc_ipv4_comparator(const void *p1, const void *p2)
{
	const struct dp_virtsvc *l = *(const struct dp_virtsvc * const *)p1;
	const struct dp_virtsvc *r = *(const struct dp_virtsvc * const *)p2;

	return dp_virtsvc_ipv4_cmp(l->proto, l->virtual_addr, l->virtual_port,
							   r->proto, r->virtual_addr, r->virtual_port);
}

static int dp_virtsvc_ipv6_comparator(const void *p1, const void *p2)
{
	const struct dp_virtsvc *l = *(const struct dp_virtsvc * const *)p1;
	const struct dp_virtsvc *r = *(const struct dp_virtsvc * const *)p2;

	return dp_virtsvc_ipv6_cmp(l->proto, &l->service_addr, l->service_port,
							   r->proto, &r->service_addr, r->service_port);
}

static int dp_virtsvc_create_trees(void)
{
	int service_count = dp_virtsvc_get_count();
	struct dp_virtsvc **array;

	if (service_count <= 0)
		return DP_ERROR;

	// create an array of virtsvc pointers, sort it by IPv4, and create a balanced binary search tree from it
	array = (struct dp_virtsvc **)malloc(sizeof(struct dp_virtsvc *) * service_count);
	if (!array)
		return DP_ERROR;

	for (int i = 0; i < service_count; ++i)
		array[i] = &dp_virtservices[i];

	qsort(array, service_count, sizeof(struct dp_virtsvc *), dp_virtsvc_ipv4_comparator);

	if (DP_FAILED(dp_virtsvc_array_to_tree(&dp_virtsvc_ipv4_tree, array, 0, service_count-1))) {
		free(array);
		return DP_ERROR;
	}

	// re-sort by IPv6 and create the other tree
	qsort(array, service_count, sizeof(struct dp_virtsvc *), dp_virtsvc_ipv6_comparator);

	if (DP_FAILED(dp_virtsvc_array_to_tree(&dp_virtsvc_ipv6_tree, array, 0, service_count-1))) {
		free(array);
		return DP_ERROR;
	}

	free(array);
	return DP_OK;
}

static int dp_virtsvc_create_isolation_template(struct dp_port_rte_async_templates *template, uint16_t pf_idx)
{
	struct dp_port *port;

	// TODO hmmm, think of something better than passing pf_idx...
	port = dp_get_port_by_pf_index(pf_idx);
	if (!port) {
		DPS_LOG_ERR("Invalid pf index for virtual service isolation", DP_LOG_VALUE(pf_idx));
		return DP_ERROR;
	}

	// TODO comment about this being tcp only
	// TODO static const!
	struct rte_flow_item tcp_src_pattern[] = {
		{	.type = RTE_FLOW_ITEM_TYPE_ETH,
			.mask = &dp_flow_item_eth_mask,
		},
		{	.type = RTE_FLOW_ITEM_TYPE_IPV6,
			.mask = &dp_flow_item_ipv6_src_mask,
		},
		{	.type = RTE_FLOW_ITEM_TYPE_TCP,
			.mask = &dp_flow_item_tcp_src_mask,
		},
		{	.type = RTE_FLOW_ITEM_TYPE_END,
		},
	};

	// TODO Static const
	struct rte_flow_pattern_template_attr pattern_template_attr = {
		.ingress = 1,
	};

	struct rte_flow_pattern_template *pattern_template;
	struct rte_flow_error error;

	pattern_template = rte_flow_pattern_template_create(port->port_id, &pattern_template_attr, tcp_src_pattern, &error);
	if (!pattern_template){
		// TODO duplicate to dp_rte_async_flow.c
		DPS_LOG_ERR("Failed to create async flow pattern template",
						DP_LOG_PORTID(port->port_id), DP_LOG_RET(rte_errno), DP_LOG_FLOW_ERROR(error.message));
		// TODO rollback
		return DP_ERROR;
	}
	// TODO wait, needed??
	template->pattern_templates[0] = pattern_template;

	// TODO static const
	struct rte_flow_action queue_action[] = {
		{	.type = RTE_FLOW_ACTION_TYPE_QUEUE, },
		{	.type = RTE_FLOW_ACTION_TYPE_END, },
	};
	// TODO Static const
	struct rte_flow_actions_template_attr action_template_attr = {
		.ingress = 1,
	};

	struct rte_flow_actions_template *actions_template;

	actions_template = rte_flow_actions_template_create(port->port_id, &action_template_attr, queue_action, queue_action, &error);
	if (!actions_template){
		// TODO duplicate to dp_rte_async_flow.c
		DPS_LOG_ERR("Failed to create async flow action template",
						DP_LOG_PORTID(port->port_id), DP_LOG_RET(rte_errno), DP_LOG_FLOW_ERROR(error.message));
		// TODO rollback
		return DP_ERROR;
	}
	// TODO wait, needed??
	template->action_templates[0] = actions_template;

	// TODO this is duplicate of static in dp_rte_async_flow.c!
	// TODO at least make ti static
	struct rte_flow_template_table_attr table_attr = {
		.flow_attr = {
			.group = 0,
			.ingress = 1,
		},
		.nb_flows = DP_ASYNC_FLOW_PF_DEFAULT_TABLE_MAX_RULES,
	};

	struct rte_flow_template_table *table;

	table = rte_flow_template_table_create(port->port_id, &table_attr, template->pattern_templates, 1, template->action_templates, 1, &error);
	if (!table) {
		// TODO duplicate to dp_rte_async_flow.c
		DPS_LOG_ERR("Failed to create async flow table template",
						DP_LOG_PORTID(port->port_id), DP_LOG_RET(rte_errno), DP_LOG_FLOW_ERROR(error.message));
		// TODO rollback?
		return DP_ERROR;
	}

	template->template_tables[0] = table;
	return DP_OK;
}

static int dp_virstvc_free_isolation_template(struct dp_port_rte_async_templates *template, uint16_t pf_idx)
{
	struct dp_port *port;
	struct rte_flow_error error;
	int ret;

	// TODO hmmm, think of something better than passing pf_idx...
	port = dp_get_port_by_pf_index(pf_idx);
	if (!port) {
		DPS_LOG_ERR("Invalid pf index for virtual service isolation", DP_LOG_VALUE(pf_idx));
		return DP_ERROR;
	}

	// TODO check for null due to callback calling? test this

	// TODO this seems like it should call somethign of Taos
	ret = rte_flow_template_table_destroy(port->port_id, template->template_tables[0], &error);
	if (DP_FAILED(ret)) {
		DPS_LOG_ERR("Failed to destroy template table", DP_LOG_RET(ret), DP_LOG_PORTID(port->port_id), DP_LOG_FLOW_ERROR(error.message));
		return ret;
	}

	ret = rte_flow_pattern_template_destroy(port->port_id, template->pattern_templates[0], &error);
	if (DP_FAILED(ret)) {
		DPS_LOG_ERR("Failed to destroy virtsvc pattern template", DP_LOG_RET(ret), DP_LOG_PORTID(port->port_id), DP_LOG_FLOW_ERROR(error.message));
		return ret;
	}

	ret = rte_flow_actions_template_destroy(port->port_id, template->action_templates[0], &error);
	if (DP_FAILED(ret)) {
		DPS_LOG_ERR("Failed to destroy virstvc action template", DP_LOG_RET(ret), DP_LOG_PORTID(port->port_id), DP_LOG_FLOW_ERROR(error.message));
		return ret;
	}

	return DP_OK;
}

static int dp_virtsvc_init_isolation(void)  // TODO _templates?
{
	// TAP devices do not support offloading/isolation
	if (dp_conf_get_nic_type() == DP_CONF_NIC_TYPE_TAP)
		return DP_OK;

	// TODO currently only multiport-eswitch mode is done here
	// TODO(plague): move the normal eswitch mode here too
	if (!dp_conf_is_mesw_mode())
		return DP_OK;

	if (DP_FAILED(dp_virtsvc_create_isolation_template(&virtsvc_async_templates[0], 0))
		|| DP_FAILED(dp_virtsvc_create_isolation_template(&virtsvc_async_templates[1], 1)))  // TODO can alredy use pf_idx I guess inside
		return DP_ERROR;

	return DP_OK;
}

// TODO(plague) do rollback tests!
static int dp_virtsvc_free_isolation(void)  // TODO _templates?
{
	int ret1, ret2;

	// TODO check null due to rollback calling convention (and no sync/sync check here)
	ret1 = dp_virstvc_free_isolation_template(&virtsvc_async_templates[0], 0);  // TODO dp_get_pf_port_by_index inside
	ret2 = dp_virstvc_free_isolation_template(&virtsvc_async_templates[1], 1);  // TODO dp_get_pf_port_by_index inside
	return DP_FAILED(ret1) ? ret1 : ret2;
}

int dp_virtsvc_init(int socket_id)
{
	const struct dp_conf_virtual_services *rules = dp_conf_get_virtual_services();
	struct dp_conf_virtsvc *rule;
	char hashtable_name[32];  // max is 'virtsvc_table_4294967295'

	if (!rules->nb_entries)
		return DP_OK;

	dp_virtservices = (struct dp_virtsvc *)rte_zmalloc("virtual_services",
													   sizeof(struct dp_virtsvc) * rules->nb_entries,
													   RTE_CACHE_LINE_SIZE);
	if (!dp_virtservices) {
		DPS_LOG_ERR("Cannot allocate virtual services table");
		return DP_ERROR;
	}

	if (DP_FAILED(dp_virtsvc_init_isolation())) {
		DPS_LOG_ERR("Cannot initialize virtual services isolation templates");
		dp_virtsvc_free();  // TODO test this rollback
		return DP_ERROR;
	}

	dp_virtservices_end = dp_virtservices;
	for (int i = 0; i < rules->nb_entries; ++i) {
		rule = &rules->entries[i];
		dp_virtservices_end->proto = rule->proto;
		dp_virtservices_end->virtual_addr = rule->virtual_addr;
		dp_virtservices_end->virtual_port = rule->virtual_port;
		dp_virtservices_end->service_port = rule->service_port;
		dp_copy_ipv6(&dp_virtservices_end->service_addr, &rule->service_addr);
		// last_assigned_port is 0 due to zmalloc()
		snprintf(hashtable_name, sizeof(hashtable_name), "virtsvc_table_%u", i);
		dp_virtservices_end->open_ports = dp_create_jhash_table(DP_VIRTSVC_PORTCOUNT,
																sizeof(struct dp_virtsvc_conn_key),
																hashtable_name,
																socket_id);
		if (!dp_virtservices_end->open_ports) {
			DPS_LOG_ERR("Cannot allocate connection table", _DP_LOG_INT("virtsvc_entry", i));
			dp_virtsvc_free();
			return DP_ERROR;
		}
		dp_virtservices_end++;
	}

	if (DP_FAILED(dp_virtsvc_create_trees())) {
		DPS_LOG_ERR("Failed to build lookup trees");
		dp_virtsvc_free();
		return DP_ERROR;
	}

#ifdef ENABLE_PYTEST
	port_timeout = dp_conf_get_flow_timeout();
	fast_timeout = port_timeout != DP_FLOW_DEFAULT_TIMEOUT;
#endif
	port_timeout *= rte_get_timer_hz();
	established_port_timeout *= rte_get_timer_hz();

	return DP_OK;
}

static void dp_virtsvc_free_tree(struct dp_virtsvc_lookup_entry *tree)
{
	if (!tree)
		return;
	dp_virtsvc_free_tree(tree->left);
	dp_virtsvc_free_tree(tree->right);
	free(tree);
}

static void dp_virtsvc_remove_isolation(struct dp_virtsvc *virtsvc, uint16_t pf_idx)
{
	struct dp_port *port;
	int ret;

	port = dp_get_port_by_pf_index(pf_idx);
	if (!port) {
		DPS_LOG_ERR("Invalid PF index for virtual service isolation cleanup", DP_LOG_VALUE(pf_idx));
		return;
	}

	// TODO connected to the test suite, but needed for rollback anyway
	// TODO this fails if PF0 init fails, but this should be solved automatically by proper virtsvc islation implementation
	if (!virtsvc->isolation_rules[pf_idx]) {
		DPS_LOG_ERR("No rule for index", DP_LOG_VALUE(pf_idx));
		return;
	}

	ret = dp_destroy_async_rules(port->port_id, &virtsvc->isolation_rules[pf_idx], 1);
	if (DP_FAILED(ret)) {
		DPS_LOG_ERR("Cannot destroy async virtual service isolation rule", DP_LOG_VIRTSVC(virtsvc), DP_LOG_RET(ret));
		return;
	}

	// TODO do this here for simplicity or in a bulk? because there can be >64 (current max) virstsvcs anyway...
	// TODO recheck logs
	// TODO obsolete due to the above call, rewrite!
// 	if (DP_FAILED(dp_commit_rte_async_flow_rules(port->port_id, 1)))
// 		DPS_LOG_ERR("Failed to commit the destruction of async virtsvc isolation", DP_LOG_PORTID(port->port_id));  // TODO ret(inside)
}

void dp_virtsvc_free(void)
{
	dp_virtsvc_free_tree(dp_virtsvc_ipv4_tree);
	dp_virtsvc_free_tree(dp_virtsvc_ipv6_tree);
	DP_FOREACH_VIRTSVC(&dp_virtservices, service) {
		// TODO free isolation rules here
		// TODO ifs?
		// TODO Maybe do both at once inside and then push+pull
		dp_virtsvc_remove_isolation(service, 0);
		dp_virtsvc_remove_isolation(service, 1);
		dp_free_jhash_table(service->open_ports);
	}
	dp_virtsvc_free_isolation();
	rte_free(dp_virtservices);
}

int dp_virtsvc_get_count(void)
{
	// conversion is fine, will never get that far
	return (int)(dp_virtservices_end - dp_virtservices);
}


// TODO if seperated here, then do a DPS_LOG_INFO("Init isolation flow rule for IPinIP tunnels"); message
int dp_virtsvc_install_sync_isolation_rules(uint16_t port_id)
{
	int ret;

	DP_FOREACH_VIRTSVC(&dp_virtservices, service) {
		ret = dp_install_isolated_mode_virtsvc(port_id,
											   service->proto,
											   &service->service_addr,
											   service->service_port);
		if (DP_FAILED(ret)) {
			DPS_LOG_ERR("Cannot create isolation rule", DP_LOG_VIRTSVC(service), DP_LOG_RET(ret));
			return DP_ERROR;
		}
	}
	return DP_OK;
}

static int dp_virtsvc_install_async_isolation(uint16_t port_id, uint8_t proto_id, const union dp_ipv6 *svc_ipv6, rte_be16_t svc_port, struct rte_flow **p_flow, struct rte_flow_template_table *template_tables[])
{
	// TODO rename concrete_patterns to pattern singular as per RTE
	// TODO without mask we need to zero these, which is against the intent of the whole header, look into it
// 	struct rte_flow_item_eth eth_spec = {0};    // #1
// 	struct rte_flow_item_ipv6 ipv6_spec = {0};  // #2
// 	struct rte_flow_item_tcp tcp_spec = {0};    // #3 (choose one)
// 	struct rte_flow_item_udp udp_spec = {0};    // #3 (choose one)
// 	struct rte_flow_item concrete_patterns[4];  // + end
// 	int concrete_pattern_cnt = 0;
// 	struct rte_flow_action_queue queue_action = {0};  // #1
// 	struct rte_flow_action concrete_actions[2]; // + end
// 	int concrete_action_cnt = 0;

	// TODO I dont think this can be shared with islocation rules
	struct rte_flow_item_eth eth_spec = {
		.hdr.ether_type = htons(RTE_ETHER_TYPE_IPV6),
	};
	struct rte_flow_item_ipv6 ipv6_spec = {
		.hdr.proto = proto_id,
		// cannot set IPv6 here as it's an array // TODO? .hdr.src_addr = { svc_ipv6->bytes[0], ... },
	};
	dp_set_src_ipv6(&ipv6_spec.hdr, svc_ipv6);  // TODO this can be done via a macro in the init itself...
	struct rte_flow_item_tcp tcp_spec = {
		.hdr.src_port = svc_port,
	};
	// TODO udp, either separate func or just fill in both and then ternary in the table
	// TODO validate proto_id to be only UDP/TCP!
	struct rte_flow_item concrete_patterns[] = {
		{	.type = RTE_FLOW_ITEM_TYPE_ETH,
			.spec = &eth_spec,
		},
		{	.type = RTE_FLOW_ITEM_TYPE_IPV6,
			.spec = &ipv6_spec,
		},
		{	.type = RTE_FLOW_ITEM_TYPE_TCP,
			.spec = &tcp_spec,
		},
		{	.type = RTE_FLOW_ITEM_TYPE_END },
	};

	// create match pattern: IPv6 packets from selected addresses
// 	dp_set_eth_flow_item(&concrete_patterns[concrete_pattern_cnt++], &eth_spec, htons(RTE_ETHER_TYPE_IPV6), DP_SET_FLOW_ITEM_WITHOUT_MASK);
// 	dp_set_ipv6_src_flow_item(&concrete_patterns[concrete_pattern_cnt++], &ipv6_spec, svc_ipv6, proto_id, DP_SET_FLOW_ITEM_WITHOUT_MASK);
// 	if (proto_id == IPPROTO_TCP) {
// 		dp_set_tcp_src_flow_item(&concrete_patterns[concrete_pattern_cnt++], &tcp_spec, svc_port, DP_SET_FLOW_ITEM_WITHOUT_MASK);
// TODO not implemented yet!
// 	} else if (proto_id == IPPROTO_UDP) {
// 		dp_set_udp_src_flow_item(&concrete_patterns[concrete_pattern_cnt++], &udp_spec, svc_port, DP_SET_FLOW_ITEM_WITHOUT_MASK);
// 	} else {
// 		DPS_LOG_ERR("Invalid virtsvc protocol for isolation", DP_LOG_PROTO(proto_id));
// 		return DP_ERROR;
// 	}
// 	dp_set_end_flow_item(&concrete_patterns[concrete_pattern_cnt++]);

	// TODO shared with isolation rules, move this function
	struct rte_flow_action_queue queue_action = {
		.index = 0,
	};
	struct rte_flow_action concrete_actions[] = {
		{	.type = RTE_FLOW_ACTION_TYPE_QUEUE,
			.conf = &queue_action,
		},
		{	.type = RTE_FLOW_ACTION_TYPE_END },
	};

	// create flow action: allow packets to enter dp-service packet queue
// 	dp_set_redirect_queue_action(&concrete_actions[concrete_action_cnt++], &queue_action, 0);
// 	dp_set_end_action(&concrete_actions[concrete_action_cnt++]);

	// TODO needed or simply write into?
	struct rte_flow *created_flow;
	struct rte_flow_error error;
	// TODO static const?
	struct rte_flow_op_attr op_attr = { .postpone = 1 };  // TODO do we actually want to postpone? -> yes it prevent push, but not the pull unfortunately

	created_flow = rte_flow_async_create(port_id, 0, &op_attr, template_tables[0],  // TODO better argument instead of the tables?
			concrete_patterns, 0, concrete_actions, 0, NULL, &error);
	if (!created_flow) {
		DPS_LOG_ERR("Failed to create concrete async virstvc rule", DP_LOG_RET(rte_errno), DP_LOG_PORTID(port_id), DP_LOG_FLOW_ERROR(error.message));
		return DP_ERROR;
	}

	*p_flow = created_flow;  // TODO get rid of this p_flow
	return DP_OK;
}

int dp_virtsvc_install_async_isolation_rules(uint16_t port_id)
{
	uint8_t rule_count = 0;  // TODO type?
	uint16_t pf_idx;
	int ret;

	// TODO rollback missing everywhere

	// TODO this needs making better!
	if (port_id == dp_get_pf0()->port_id)
		pf_idx = 0;
	else if (port_id == dp_get_pf1()->port_id)
		pf_idx = 1;
	else {
		DPS_LOG_ERR("Invalid port for virtual service isolation", DP_LOG_PORTID(port_id));
		return DP_ERROR;
	}

	DP_FOREACH_VIRTSVC(&dp_virtservices, service) {
		// TODO pass service itself (and maybe pf idx), but that can only happen *after* we remove the p_flow argument
		ret = dp_virtsvc_install_async_isolation(port_id,
													 service->proto,
													 &service->service_addr,
													 service->service_port,
													 &service->isolation_rules[pf_idx],
													 virtsvc_async_templates[pf_idx].template_tables);
		if (DP_FAILED(ret)) {
			DPS_LOG_ERR("Cannot create async virtsvc isolation rule", DP_LOG_VIRTSVC(service), DP_LOG_RET(ret));
			return DP_ERROR;
		}
		rule_count++;
	}

	// TODO code duplication, there needs to be some "blocking push" or something as a single call
	if (DP_FAILED(dp_commit_rte_async_flow_rules(port_id, rule_count))) {
		DPS_LOG_ERR("TODO Failed to commit async virtsvc isolation rules ", DP_LOG_PORTID(port_id));
		return DP_ERROR;
	}

	return DP_OK;
}


static __rte_always_inline bool dp_virtsvc_is_connection_old(struct dp_virtsvc_conn *conn, uint64_t current_tsc)
{
	uint64_t timeout = conn->last_pkt_timestamp + (conn->state == DP_VIRTSVC_CONN_ESTABLISHED
														? established_port_timeout
														: port_timeout);

	return current_tsc > timeout;
}

static __rte_always_inline int dp_virtsvc_get_free_port(struct dp_virtsvc *virtsvc)
{
	uint64_t current_tsc = rte_get_timer_cycles();

#ifdef ENABLE_PYTEST
	// flow timeout is being tested, try to revisit already used ports
	if (fast_timeout)
		virtsvc->last_assigned_port = 0;
#endif

	for (uint16_t port = virtsvc->last_assigned_port+1; port < DP_VIRTSVC_PORTCOUNT; ++port)
		if (dp_virtsvc_is_connection_old(&virtsvc->connections[port], current_tsc))
			return virtsvc->last_assigned_port = port;

	for (uint16_t port = 0; port <= virtsvc->last_assigned_port; ++port)
		if (dp_virtsvc_is_connection_old(&virtsvc->connections[port], current_tsc))
			return virtsvc->last_assigned_port = port;

	DPS_LOG_WARNING("Out of virtsvc ports", DP_LOG_VIRTSVC(virtsvc));
	return DP_ERROR;
}

static __rte_always_inline int dp_virtsvc_create_connection(struct dp_virtsvc *virtsvc,
															struct dp_virtsvc_conn_key *key,
															hash_sig_t sig)
{
	struct dp_virtsvc_conn_key delete_key;
	struct dp_virtsvc_conn *conn;
	uint16_t free_port;
	int ret;

	ret = dp_virtsvc_get_free_port(virtsvc);
	if (DP_FAILED(ret))
		return ret;

	free_port = (uint16_t)ret;
	conn = &virtsvc->connections[free_port];

	if (conn->last_pkt_timestamp) {
		delete_key.vf_port_id = conn->vf_port_id;
		delete_key.vf_l4_port = conn->vf_l4_port;
		delete_key.vf_ip = conn->vf_ip;
		ret = rte_hash_del_key(virtsvc->open_ports, &delete_key);
		if (DP_FAILED(ret))
			DPS_LOG_WARNING("Cannot delete virtual service NAT entry", DP_LOG_RET(ret),
							DP_LOG_PORTID(conn->vf_port_id), DP_LOG_L4PORT(conn->vf_l4_port));
	}

	ret = rte_hash_add_key_with_hash_data(virtsvc->open_ports, key, sig, (void *)(intptr_t)free_port);
	if (DP_FAILED(ret))
		return ret;

	conn->vf_ip = key->vf_ip;
	conn->vf_l4_port = key->vf_l4_port;
	conn->vf_port_id = key->vf_port_id;
	conn->state = DP_VIRTSVC_CONN_TRANSIENT;

	return free_port;
}

static __rte_always_inline int dp_virstvc_get_connection(struct dp_virtsvc *virtsvc,
														 struct dp_virtsvc_conn_key *key,
														 hash_sig_t sig)
{
	void *data;
	int ret;

	ret = rte_hash_lookup_with_hash_data(virtsvc->open_ports, key, sig, &data);
	if (DP_FAILED(ret))
		return ret;

	assert((intptr_t)data >= 0 && (intptr_t)data < DP_VIRTSVC_PORTCOUNT);
	return (int)(intptr_t)data;
}

int dp_virtsvc_get_pf_route(struct dp_virtsvc *virtsvc,
							 uint16_t vf_port_id,
							 rte_be32_t vf_ip,
							 rte_be16_t vf_l4_port,
							 uint16_t *pf_port_id,
							 int *conn_idx)
{
	struct dp_virtsvc_conn_key key = {
		.vf_port_id = vf_port_id,
		.vf_l4_port = vf_l4_port,
		.vf_ip = vf_ip,
	};
	hash_sig_t key_hash = rte_hash_hash(virtsvc->open_ports, &key);
	int ret;

	ret = dp_virstvc_get_connection(virtsvc, &key, key_hash);
	if (ret == -ENOENT)
		ret = dp_virtsvc_create_connection(virtsvc, &key, key_hash);
	if (DP_FAILED(ret)) {
		DPS_LOG_WARNING("Cannot create virtsvc connection", DP_LOG_VIRTSVC(virtsvc), DP_LOG_RET(ret));
		return ret;
	}

	*conn_idx = ret;

	static_assert(sizeof(key_hash) == sizeof(uint32_t), "Virtsvc key is not 32b integer");
	*pf_port_id = dp_multipath_get_pf(key_hash)->port_id;

	return DP_OK;
}


void dp_virtsvc_del_iface(uint16_t port_id)
{
	struct dp_virtsvc_conn_key delete_key;
	struct dp_virtsvc_conn *conn;
	int ret;

	DP_FOREACH_VIRTSVC(&dp_virtservices, service) {
		// This seems sub-optimal as it always checks *all* ports.
		// But in practice, the port table is always full anyway
		// as timed-out connections get replaced with new ones on-demand
		// (i.e. the table is constantly full after the first 64k connections)
		for (size_t i = 0; i < RTE_DIM(service->connections); ++i) {
			conn = &service->connections[i];
			if (conn->vf_port_id == port_id && conn->last_pkt_timestamp) {
				conn->last_pkt_timestamp = 0;
				delete_key.vf_port_id = conn->vf_port_id;
				delete_key.vf_l4_port = conn->vf_l4_port;
				delete_key.vf_ip = conn->vf_ip;
				ret = rte_hash_del_key(service->open_ports, &delete_key);
				if (DP_FAILED(ret))
					DPS_LOG_WARNING("Cannot delete virtual service NAT entry", DP_LOG_RET(ret),
							DP_LOG_PORTID(conn->vf_port_id), DP_LOG_L4PORT(conn->vf_l4_port));
			}
		}
	}
}

static inline uint64_t dp_virtsvc_get_used_port_count(struct dp_virtsvc *virtsvc)
{
	uint64_t used_ports = 0;
	uint64_t current_tsc = rte_get_timer_cycles();

	for (int port = 0; port < DP_VIRTSVC_PORTCOUNT; ++port) {
		if (!dp_virtsvc_is_connection_old(&virtsvc->connections[port], current_tsc))
			++used_ports;
	}
	return used_ports;
}

int dp_virtsvc_get_used_ports_telemetry(struct rte_tel_data *dict)
{
	int ret;
	char virtsvc_name[DP_VIRTSVC_TELEMETRY_MAX_NAME_SIZE];

	DP_FOREACH_VIRTSVC(&dp_virtservices, service) {
		snprintf(virtsvc_name, sizeof(virtsvc_name),
				 "%s:" DP_IPV4_PRINT_FMT ":%u",
				 service->proto == IPPROTO_TCP ? "TCP" : "UDP",
				 DP_IPV4_PRINT_BYTES(service->virtual_addr),
				 ntohs(service->virtual_port));
		ret = rte_tel_data_add_dict_u64(dict, virtsvc_name, dp_virtsvc_get_used_port_count(service));
		if (DP_FAILED(ret)) {
			DPS_LOG_ERR("Failed to add virtsvc telemetry data", DP_LOG_RET(ret));
			return ret;
		}
	}
	return DP_OK;
}
