// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#include "rte_flow/dp_rte_async_flow_isolation.h"
#include "dp_error.h"

static const struct rte_flow_action_queue isolation_queue_action = {
	.index = 0,
};

static const struct rte_flow_action isolation_actions[] = {
	{	.type = RTE_FLOW_ACTION_TYPE_QUEUE,
		.conf = &isolation_queue_action,
	},
	{	.type = RTE_FLOW_ACTION_TYPE_END },
};

// proto_id is either IPPROTO_IPIP or IPPROTO_IPV6
static int dp_create_concrete_async_default_rule_for_pf(uint16_t port_id, uint8_t proto_id)
{
	struct dp_port *port = dp_get_port_by_id(port_id);
	int ret;
	struct rte_flow *flow;

	struct rte_flow_item_eth eth_spec = {
		.hdr.ether_type = htons(RTE_ETHER_TYPE_IPV6),
	};
	struct rte_flow_item_ipv6 ipv6_spec = {
		.hdr.proto = proto_id,
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

	ret = dp_rte_async_create_concrete_rules(port_id, port->default_async_rules.async_templates[DP_ASYNC_TEMPLATE_TABLE_PF_ISOLATION].template_table,
											pattern, isolation_actions,
											DP_ASYNC_TEMPLATE_PATTERN_PF_IPV6_PROTO, DP_ASYNC_TEMPLATE_ACTION_PF_QUEUE,
											&flow);
	if (DP_FAILED(ret)) {
		DPS_LOG_ERR("Failed to create concrete async default rule for pf", DP_LOG_PORTID(port_id));
		return DP_ERROR;
	}

	if (proto_id == IPPROTO_IPIP)
		port->default_async_rules.default_async_flow[0] = flow;
	else
		port->default_async_rules.default_async_flow[1] = flow;

	return DP_OK;
}

int dp_create_pf_async_isolation_rules(uint16_t port_id)
{
	// TODO missing rollback
	if (DP_FAILED(dp_create_concrete_async_default_rule_for_pf(port_id, IPPROTO_IPIP)) ||
			DP_FAILED(dp_create_concrete_async_default_rule_for_pf(port_id, IPPROTO_IPV6))) {
			DPS_LOG_ERR("Failed to install async isolation rules for pf", DP_LOG_PORTID(port_id));
			return DP_ERROR;
	}

	if (DP_FAILED(dp_push_rte_async_flow_rules(port_id))) {
		DPS_LOG_ERR("Failed to above async isolation rules installed on main eswitch port to HW", DP_LOG_PORTID(port_id));
		return DP_ERROR;
	}

	if (DP_FAILED(dp_pull_rte_async_rule_status(port_id, 2))) {
		DPS_LOG_ERR("Failed to pull the status of the 2 above async isolation rules installed on main eswitch port to HW", DP_LOG_PORTID(port_id));
		return DP_ERROR;
	}

	return DP_OK;
}

int dp_destroy_pf_async_isolation_rules(uint16_t port_id)
{
	struct dp_port *port = dp_get_port_by_id(port_id);

	for (uint8_t i = 0; i < DP_ASYNC_DEFAULT_FLOW_ON_PF_CNT; i++) {
		struct rte_flow *flow_to_destroy = port->default_async_rules.default_async_flow[i];
		if (DP_FAILED(dp_rte_async_destroy_rule(port_id, flow_to_destroy)))
			DPS_LOG_WARNING("Failed to enqueue the operation of destroying pf async isolation rule", DP_LOG_PORTID(port_id));
	}

	if (DP_FAILED(dp_push_rte_async_flow_rules(port_id))) {
		DPS_LOG_WARNING("Failed to push the operation of destroying above async isolation on main eswitch port to HW", DP_LOG_PORTID(port_id));
		return DP_ERROR;
	}

	if (DP_FAILED(dp_pull_rte_async_rule_status(port_id, 2))) {
		DPS_LOG_ERR("Failed to pull the status of the operation of destroying 2 above async isolation rules on main eswitch port to HW", DP_LOG_PORTID(port_id));
		return DP_ERROR;
	}

	return DP_OK;
}
