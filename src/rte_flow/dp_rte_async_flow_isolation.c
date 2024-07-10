// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#include "rte_flow/dp_rte_async_flow_isolation.h"

#include "dp_error.h"
#ifdef ENABLE_VIRTSVC
#include "dp_virtsvc.h"
#endif
#include "rte_flow/dp_rte_async_flow.h"
#include "rte_flow/dp_rte_async_flow_template.h"
#include "rte_flow/dp_rte_flow_helpers.h"

#define DP_ISOLATION_DEFAULT_TABLE_MAX_RULES 8

enum dp_isolation_pattern_type {
	DP_ISOLATION_PATTERN_IPV6_PROTO,
	DP_ISOLATION_PATTERN_COUNT,
};

enum dp_isolation_actions_type {
	DP_ISOLATION_ACTIONS_QUEUE,
	DP_ISOLATION_ACTIONS_COUNT,
};

static const struct rte_flow_pattern_template_attr default_pattern_template_attr = {
	.ingress = 1
};

static const struct rte_flow_actions_template_attr default_actions_template_attr = {
	.ingress = 1
};

static const struct rte_flow_template_table_attr pf_default_template_table_attr = {
	.flow_attr = {
		.group = 0,
		.ingress = 1,
	},
	.nb_flows = DP_ISOLATION_DEFAULT_TABLE_MAX_RULES,
	// TODO? .specialize = RTE_FLOW_TABLE_SPECIALIZE_TRANSFER_WIRE_ORIG,
};

int dp_create_pf_async_isolation_templates(struct dp_port *port) {

	struct dp_port_async_template *tmpl;

	tmpl = dp_alloc_async_template(DP_ISOLATION_PATTERN_COUNT, DP_ISOLATION_ACTIONS_COUNT);
	if (!tmpl)
		return DP_ERROR;

	port->default_async_rules.default_templates[DP_PORT_ASYNC_TEMPLATE_PF_ISOLATION] = tmpl;

	// no need to check returned values here, dp_create_async_template() takes care of everything

	static const struct rte_flow_item pattern[] = {
		{	.type = RTE_FLOW_ITEM_TYPE_ETH,
			.mask = &dp_flow_item_eth_mask,
		},
		{	.type = RTE_FLOW_ITEM_TYPE_IPV6,
			.mask = &dp_flow_item_ipv6_mask,
		},
		{	.type = RTE_FLOW_ITEM_TYPE_END,
		},
	};
	tmpl->pattern_templates[DP_ISOLATION_PATTERN_IPV6_PROTO]
		= dp_create_async_pattern_template(port->port_id, &default_pattern_template_attr, pattern);

	static const struct rte_flow_action actions[] = {
		{	.type = RTE_FLOW_ACTION_TYPE_QUEUE, },
		{	.type = RTE_FLOW_ACTION_TYPE_END, },
	};
	tmpl->actions_templates[DP_ISOLATION_ACTIONS_QUEUE]
		= dp_create_async_actions_template(port->port_id, &default_actions_template_attr, actions, actions);

	tmpl->table_attr = &pf_default_template_table_attr;

	return dp_init_async_template(port->port_id, tmpl);
}

#ifdef ENABLE_VIRTSVC
int dp_create_virtsvc_async_isolation_templates(struct dp_port *port, uint8_t proto_id)
{
	struct dp_port_async_template *template;

	template = dp_alloc_async_template(DP_ISOLATION_PATTERN_COUNT, DP_ISOLATION_ACTIONS_COUNT);
	if (!template)
		return DP_ERROR;

	if (proto_id == IPPROTO_TCP)
		port->default_async_rules.default_templates[DP_PORT_ASYNC_TEMPLATE_VIRTSVC_TCP_ISOLATION] = template;
	else
		port->default_async_rules.default_templates[DP_PORT_ASYNC_TEMPLATE_VIRTSVC_UDP_ISOLATION] = template;

	const struct rte_flow_item tcp_src_pattern[] = {
		{	.type = RTE_FLOW_ITEM_TYPE_ETH,
			.mask = &dp_flow_item_eth_mask,
		},
		{	.type = RTE_FLOW_ITEM_TYPE_IPV6,
			.mask = &dp_flow_item_ipv6_src_mask,
		},
		{	.type = proto_id == IPPROTO_TCP ? RTE_FLOW_ITEM_TYPE_TCP : RTE_FLOW_ITEM_TYPE_UDP,
			.mask = proto_id == IPPROTO_TCP ? (const void *)&dp_flow_item_tcp_src_mask : (const void *)&dp_flow_item_udp_src_mask,
		},
		{	.type = RTE_FLOW_ITEM_TYPE_END,
		},
	};
	template->pattern_templates[DP_ISOLATION_PATTERN_IPV6_PROTO]
		= dp_create_async_pattern_template(port->port_id, &default_pattern_template_attr, tcp_src_pattern);

	static const struct rte_flow_action actions[] = {
		{	.type = RTE_FLOW_ACTION_TYPE_QUEUE, },
		{	.type = RTE_FLOW_ACTION_TYPE_END, },
	};
	template->actions_templates[DP_ISOLATION_ACTIONS_QUEUE]
		= dp_create_async_actions_template(port->port_id, &default_actions_template_attr, actions, actions);

	template->table_attr = &pf_default_template_table_attr;

	return dp_init_async_template(port->port_id, template);
}
#endif


static struct rte_flow *dp_create_pf_async_isolation_rule(uint16_t port_id, uint8_t proto, struct rte_flow_template_table *template_table)
{
	struct rte_flow_item_eth eth_spec = {
		.hdr.ether_type = htons(RTE_ETHER_TYPE_IPV6),
	};
	struct rte_flow_item_ipv6 ipv6_spec = {
		.hdr.proto = proto,
	};
	struct rte_flow_item pattern[] = {
		{	.type = RTE_FLOW_ITEM_TYPE_ETH,
			.spec = &eth_spec,
		},
		{	.type = RTE_FLOW_ITEM_TYPE_IPV6,
			.spec = &ipv6_spec,
		},
		{	.type = RTE_FLOW_ITEM_TYPE_END },
	};

	static const struct rte_flow_action_queue queue_action = {
		.index = 0,
	};
	static const struct rte_flow_action actions[] = {
		{	.type = RTE_FLOW_ACTION_TYPE_QUEUE,
			.conf = &queue_action,
		},
		{	.type = RTE_FLOW_ACTION_TYPE_END },
	};

	return dp_create_async_rule(port_id, template_table,
								pattern, DP_ISOLATION_PATTERN_IPV6_PROTO,
								actions, DP_ISOLATION_ACTIONS_QUEUE);
}

#ifdef ENABLE_VIRTSVC
struct rte_flow *dp_create_virtsvc_async_isolation_rule(uint16_t port_id, uint8_t proto_id,
														const union dp_ipv6 *svc_ipv6, rte_be16_t svc_port,
														struct rte_flow_template_table *template_table)
{
	const struct rte_flow_item_eth eth_spec = {
		.hdr.ether_type = htons(RTE_ETHER_TYPE_IPV6),
	};
	struct rte_flow_item_ipv6 ipv6_spec = {
		.hdr.proto = proto_id,
		.hdr.src_addr = DP_INIT_FROM_IPV6(svc_ipv6),
	};
	const struct rte_flow_item_tcp tcp_spec = {
		.hdr.src_port = svc_port,
	};
	const struct rte_flow_item_udp udp_spec = {
		.hdr.src_port = svc_port,
	};
	const struct rte_flow_item pattern[] = {
		{	.type = RTE_FLOW_ITEM_TYPE_ETH,
			.spec = &eth_spec,
		},
		{	.type = RTE_FLOW_ITEM_TYPE_IPV6,
			.spec = &ipv6_spec,
		},
		{	.type = proto_id == IPPROTO_TCP ? RTE_FLOW_ITEM_TYPE_TCP : RTE_FLOW_ITEM_TYPE_UDP,
			.spec = proto_id == IPPROTO_TCP ? (const void *)&tcp_spec : (const void *)&udp_spec,
		},
		{	.type = RTE_FLOW_ITEM_TYPE_END },
	};

	static const struct rte_flow_action_queue queue_action = {
		.index = 0,
	};
	struct rte_flow_action actions[] = {
		{	.type = RTE_FLOW_ACTION_TYPE_QUEUE,
			.conf = &queue_action,
		},
		{	.type = RTE_FLOW_ACTION_TYPE_END },
	};

	return dp_create_async_rule(port_id, template_table,
								pattern, DP_ISOLATION_PATTERN_IPV6_PROTO,
								actions, DP_ISOLATION_ACTIONS_QUEUE);
}
#endif

int dp_create_pf_async_isolation_rules(struct dp_port *port)
{
	struct rte_flow *flow;
	uint16_t rule_count = 0;
	size_t rules_required = 2;
	struct dp_port_async_template **templates = port->default_async_rules.default_templates;

	flow = dp_create_pf_async_isolation_rule(port->port_id, IPPROTO_IPIP,
											 templates[DP_PORT_ASYNC_TEMPLATE_PF_ISOLATION]->template_table);
	if (!flow) {
		DPS_LOG_ERR("Failed to install PF async IPIP isolation rule", DP_LOG_PORTID(port->port_id));
		return DP_ERROR;
	} else {
		port->default_async_rules.default_flows[DP_PORT_ASYNC_FLOW_ISOLATE_IPIP] = flow;
		rule_count++;
	}

	flow = dp_create_pf_async_isolation_rule(port->port_id, IPPROTO_IPV6,
											 templates[DP_PORT_ASYNC_TEMPLATE_PF_ISOLATION]->template_table);
	if (!flow) {
		DPS_LOG_ERR("Failed to install PF async IPV6 isolation rule", DP_LOG_PORTID(port->port_id));
		// cannot return, need to commit all previous rules
	} else {
		port->default_async_rules.default_flows[DP_PORT_ASYNC_FLOW_ISOLATE_IPV6] = flow;
		rule_count++;
	}

#ifdef ENABLE_VIRTSVC
	rule_count += dp_create_virtsvc_async_isolation_rules(port->port_id,
														  templates[DP_PORT_ASYNC_TEMPLATE_VIRTSVC_TCP_ISOLATION]->template_table,
														  templates[DP_PORT_ASYNC_TEMPLATE_VIRTSVC_UDP_ISOLATION]->template_table);
	// cannot end on error, need to commit partial success
#endif

	if (dp_blocking_commit_async_rules(port->port_id, rule_count)) {
		DPS_LOG_ERR("Failed to commit PF async isolation rules", DP_LOG_PORTID(port->port_id));
		return DP_ERROR;
	}


#ifdef ENABLE_VIRTSVC
	rules_required += dp_virtsvc_get_count();
#endif
	if (rule_count != rules_required) {
		DPS_LOG_ERR("Not all PF async isolation rules were installed", DP_LOG_VALUE(rule_count), DP_LOG_MAX(rules_required), DP_LOG_PORTID(port->port_id));
		return DP_ERROR;
	}

	return DP_OK;
}
