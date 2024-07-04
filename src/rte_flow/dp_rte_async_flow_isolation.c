// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#include "rte_flow/dp_rte_async_flow_isolation.h"
#include "dp_error.h"
#include "rte_flow/dp_rte_async_flow.h"
#include "rte_flow/dp_rte_async_flow_template.h"
#include "rte_flow/dp_rte_flow_helpers.h"

// TODO names?
// TODO let's see if virtsvuc reuses this
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
	.nb_flows = DP_ASYNC_FLOW_PF_DEFAULT_TABLE_MAX_RULES,
	// TODO? .specialize = RTE_FLOW_TABLE_SPECIALIZE_TRANSFER_WIRE_ORIG,
};

int dp_create_pf_async_isolation_templates(struct dp_port *port) {

	struct dp_port_async_template *template = &port->default_async_rules.async_templates[DP_PORT_ASYNC_TEMPLATE_ISOLATION];

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
	template->pattern_templates[DP_ASYNC_PATTERN_TEMPLATE_ISOLATION_IPV6_PROTO]
		= dp_create_async_pattern_template(port->port_id, &default_pattern_template_attr, pattern);

	static const struct rte_flow_action actions[] = {
		{	.type = RTE_FLOW_ACTION_TYPE_QUEUE, },
		{	.type = RTE_FLOW_ACTION_TYPE_END, },
	};
	template->actions_templates[DP_ASYNC_ACTIONS_TEMPLATE_ISOLATION_QUEUE]
		= dp_create_async_actions_template(port->port_id, &default_actions_template_attr, actions, actions);

	template->table_attr = &pf_default_template_table_attr;

	return dp_create_async_template(port->port_id, template, DP_ASYNC_PATTERN_TEMPLATE_ISOLATION_COUNT, DP_ASYNC_ACTIONS_TEMPLATE_ISOLATION_COUNT);
}


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

	return dp_rte_flow_async_create(port_id, template_table,
									pattern, DP_ASYNC_PATTERN_TEMPLATE_ISOLATION_IPV6_PROTO,
									actions, DP_ASYNC_ACTIONS_TEMPLATE_ISOLATION_QUEUE);
}

int dp_create_pf_async_isolation_rules(struct dp_port *port)
{
	struct rte_flow *flow;
	uint16_t rule_count = 0;

	flow = dp_create_pf_async_isolation_rule(port->port_id, IPPROTO_IPIP,
											 port->default_async_rules.async_templates[DP_PORT_ASYNC_TEMPLATE_ISOLATION].template_table);
	if (!flow) {
		DPS_LOG_ERR("Failed to install PF async IPIP isolation rule", DP_LOG_PORTID(port->port_id));
	} else {
		port->default_async_rules.default_async_flows[DP_PORT_DEFAULT_ASYNC_FLOW_ISOLATE_IPIP] = flow;
		rule_count++;
	}

	flow = dp_create_pf_async_isolation_rule(port->port_id, IPPROTO_IPV6,
											 port->default_async_rules.async_templates[DP_PORT_ASYNC_TEMPLATE_ISOLATION].template_table);
	if (!flow) {
		DPS_LOG_ERR("Failed to install PF async IPV6 isolation rule", DP_LOG_PORTID(port->port_id));
	} else {
		port->default_async_rules.default_async_flows[DP_PORT_DEFAULT_ASYNC_FLOW_ISOLATE_IPV6] = flow;
		rule_count++;
	}

	// need to commit even partial success so the already created flows can be freed later
	if (dp_commit_rte_async_flow_rules(port->port_id, rule_count)) {
		DPS_LOG_ERR("Failed to commit PF async isolation rules", DP_LOG_PORTID(port->port_id));
		// if this fails, rollback is impossible, as it would also require a commit
		return DP_ERROR;
	}

	if (rule_count != 2) {
		DPS_LOG_ERR("Not all PF async isolation rules were installed", DP_LOG_VALUE(rule_count), DP_LOG_MAX(2), DP_LOG_PORTID(port->port_id));
		return DP_ERROR;
	}

	return DP_OK;
}
