// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#include "rte_flow/dp_rte_async_flow_pf1_proxy.h"
#include "rte_flow/dp_rte_async_flow.h"
#include "rte_flow/dp_rte_async_flow_template.h"
#include "rte_flow/dp_rte_flow_helpers.h"

// having MAX equal to actual number of rules impacts throughput (for unknown reason)
#define DP_PF1_DEFAULT_TABLE_MAX_RULES (DP_PF1_PROXY_RULE_COUNT+1)

enum dp_pf1_proxy_pattern_type {
	DP_PF1_PROXY_PATTERN_REPR_PORT,
	DP_PF1_PROXY_PATTERN_COUNT,
};

enum dp_pf1_proxy_actions_type {
	DP_PF1_PROXY_ACTIONS_REPR_PORT,
	DP_PF1_PROXY_ACTIONS_COUNT,
};

static const struct rte_flow_pattern_template_attr transfer_pattern_template_attr = {
	.transfer = 1
};

static const struct rte_flow_actions_template_attr transfer_actions_template_attr = {
	.transfer = 1
};

static const struct rte_flow_template_table_attr pf_transfer_template_table_attr = {
	.flow_attr = {
		.group = 0,
		.transfer = 1,
	},
	.nb_flows = DP_PF1_DEFAULT_TABLE_MAX_RULES,
};


int dp_create_pf_async_from_proxy_templates(struct dp_port *port)
{
	struct dp_port_async_template *tmpl;

	tmpl = dp_alloc_async_template(DP_PF1_PROXY_PATTERN_COUNT, DP_PF1_PROXY_ACTIONS_COUNT);
	if (!tmpl)
		return DP_ERROR;

	port->default_async_rules.default_templates[DP_PORT_ASYNC_TEMPLATE_PF1_FROM_PROXY] = tmpl;

	static const struct rte_flow_item pattern[] = {
		{	.type = RTE_FLOW_ITEM_TYPE_REPRESENTED_PORT,
			.mask = &dp_flow_item_ethdev_mask,
		},
		{	.type = RTE_FLOW_ITEM_TYPE_END },
	};
	tmpl->pattern_templates[DP_PF1_PROXY_PATTERN_REPR_PORT]
		= dp_create_async_pattern_template(port->port_id, &transfer_pattern_template_attr, pattern);

	static const struct rte_flow_action actions[] = {
		{	.type = RTE_FLOW_ACTION_TYPE_REPRESENTED_PORT, },
		{	.type = RTE_FLOW_ACTION_TYPE_END, },
	};
	tmpl->actions_templates[DP_PF1_PROXY_ACTIONS_REPR_PORT]
		= dp_create_async_actions_template(port->port_id, &transfer_actions_template_attr, actions, actions);

	tmpl->table_attr = &pf_transfer_template_table_attr;

	return dp_init_async_template(port->port_id, tmpl);
}

int dp_create_pf_async_to_proxy_templates(struct dp_port *port)
{
	struct dp_port_async_template *tmpl;

	tmpl = dp_alloc_async_template(DP_PF1_PROXY_PATTERN_COUNT, DP_PF1_PROXY_ACTIONS_COUNT);
	if (!tmpl)
		return DP_ERROR;

	port->default_async_rules.default_templates[DP_PORT_ASYNC_TEMPLATE_PF1_TO_PROXY] = tmpl;

	static const struct rte_flow_item pattern[] = {
		{	.type = RTE_FLOW_ITEM_TYPE_REPRESENTED_PORT,
			.mask = &dp_flow_item_ethdev_mask,
		},
		{	.type = RTE_FLOW_ITEM_TYPE_ETH,
			.mask = &dp_flow_item_eth_mask,
		},
		{	.type = RTE_FLOW_ITEM_TYPE_IPV6,
			.mask = &dp_flow_item_ipv6_dst_only_mask,
		},
		{	.type = RTE_FLOW_ITEM_TYPE_END },
	};
	tmpl->pattern_templates[DP_PF1_PROXY_PATTERN_REPR_PORT]
		= dp_create_async_pattern_template(port->port_id, &transfer_pattern_template_attr, pattern);

	static const struct rte_flow_action actions[] = {
		{	.type = RTE_FLOW_ACTION_TYPE_REPRESENTED_PORT, },
		{	.type = RTE_FLOW_ACTION_TYPE_END, },
	};
	tmpl->actions_templates[DP_PF1_PROXY_ACTIONS_REPR_PORT]
		= dp_create_async_actions_template(port->port_id, &transfer_actions_template_attr, actions, actions);

	tmpl->table_attr = &pf_transfer_template_table_attr;

	return dp_init_async_template(port->port_id, tmpl);
}


static struct rte_flow *dp_create_pf_async_from_proxy_rule(uint16_t port_id,
														   uint16_t src_port_id, uint16_t dst_port_id,
														   struct rte_flow_template_table *template_table)
{
	const struct rte_flow_item_ethdev src_port_pattern = {
		.port_id = src_port_id,
	};
	const struct rte_flow_item pattern[] = {
		{	.type = RTE_FLOW_ITEM_TYPE_REPRESENTED_PORT,
			.spec = &src_port_pattern,
		},
		{	.type = RTE_FLOW_ITEM_TYPE_END },
	};

	const struct rte_flow_item_ethdev dst_port_action = {
		.port_id = dst_port_id,
	};
	const struct rte_flow_action actions[] = {
		{	.type = RTE_FLOW_ACTION_TYPE_REPRESENTED_PORT,
			.conf = &dst_port_action,
		},
		{	.type = RTE_FLOW_ACTION_TYPE_END },
	};

	return dp_create_async_rule(port_id, template_table,
								pattern, DP_PF1_PROXY_PATTERN_REPR_PORT,
								actions, DP_PF1_PROXY_ACTIONS_REPR_PORT);
}

static struct rte_flow *dp_create_pf_async_to_proxy_rule(uint16_t port_id,
														 uint16_t src_port_id, uint16_t dst_port_id,
														 struct rte_flow_template_table *template_table)
{
	const struct rte_flow_item_ethdev src_port_pattern = {
		.port_id = src_port_id,
	};
	const struct rte_flow_item_eth eth_ipv6_pattern = {
		.type = htons(RTE_ETHER_TYPE_IPV6),
	};
	const struct rte_flow_item_ipv6 ipv6_dst_pattern = {
		.hdr.dst_addr = DP_INIT_FROM_IPV6(dp_conf_get_underlay_ip()),
	};
	const struct rte_flow_item pattern[] = {
		{	.type = RTE_FLOW_ITEM_TYPE_REPRESENTED_PORT,
			.spec = &src_port_pattern,
		},
		{	.type = RTE_FLOW_ITEM_TYPE_ETH,
			.spec = &eth_ipv6_pattern,
		},
		{	.type = RTE_FLOW_ITEM_TYPE_IPV6,
			.spec = &ipv6_dst_pattern,
		},
		{	.type = RTE_FLOW_ITEM_TYPE_END },
	};

	const struct rte_flow_item_ethdev dst_port_action = {
		.port_id = dst_port_id,
	};
	const struct rte_flow_action actions[] = {
		{	.type = RTE_FLOW_ACTION_TYPE_REPRESENTED_PORT,
			.conf = &dst_port_action,
		},
		{	.type = RTE_FLOW_ACTION_TYPE_END },
	};

	return dp_create_async_rule(port_id, template_table,
								pattern, DP_PF1_PROXY_PATTERN_REPR_PORT,
								actions, DP_PF1_PROXY_ACTIONS_REPR_PORT);
}

uint16_t dp_create_pf1_proxy_async_isolation_rules(struct dp_port *port)
{
	uint16_t pf1_port_id = dp_get_pf1()->port_id;
	uint16_t proxy_port_id = dp_get_pf1_proxy()->port_id;
	struct dp_port_async_template **templates = port->default_async_rules.default_templates;
	struct rte_flow *flow;
	uint16_t rule_count = 0;

	flow = dp_create_pf_async_from_proxy_rule(port->port_id, proxy_port_id, pf1_port_id,
											  templates[DP_PORT_ASYNC_TEMPLATE_PF1_FROM_PROXY]->template_table);
	if (!flow) {
		DPS_LOG_ERR("Failed to install PF async pf1 from proxy rule", DP_LOG_PORT(port));
		return rule_count;
	}

	port->default_async_rules.default_flows[DP_PORT_ASYNC_FLOW_PF1_FROM_PROXY] = flow;
	rule_count++;

	flow = dp_create_pf_async_to_proxy_rule(port->port_id, pf1_port_id, proxy_port_id,
											templates[DP_PORT_ASYNC_TEMPLATE_PF1_TO_PROXY]->template_table);
	if (!flow) {
		DPS_LOG_ERR("Failed to install PF async pf1 to proxy rule", DP_LOG_PORT(port));
		return rule_count;
	}

	port->default_async_rules.default_flows[DP_PORT_ASYNC_FLOW_PF1_TO_PROXY] = flow;
	rule_count++;

	return rule_count;
}
