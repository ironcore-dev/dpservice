// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#include "rte_flow/dp_rte_async_flow_isolation.h"
#include "dp_error.h"

// proto_id is either IPPROTO_IPIP or IPPROTO_IPV6
static int dp_create_concrete_async_default_rule_for_pf(uint16_t port_id, uint8_t proto_id)
{

	struct rte_flow_item_ethdev represented_port = {0}; // #1
	struct rte_flow_item_eth eth_pattern = {0};		// #2
	struct rte_flow_item_ipv6 ipv6_hdr = {0};	   // #3
	struct rte_flow_item concrete_patterns[4];  // end
	int concrete_pattern_cnt = 0;

	struct rte_flow_action_queue queue_action;  // #1
	struct rte_flow_action concrete_actions[2]; // end
	int concrete_action_cnt = 0;

	struct dp_port *main_eswitch_port = dp_get_main_eswitch_port();
	struct dp_port *port = dp_get_port_by_id(port_id);
	int ret;
	struct rte_flow *flow;

	dp_set_represented_port_item(&concrete_patterns[concrete_pattern_cnt++], &represented_port, port_id, DP_SET_FLOW_ITEM_WITHOUT_MASK);
	dp_set_eth_flow_item(&concrete_patterns[concrete_pattern_cnt++], &eth_pattern, htons(0x86DD), DP_SET_FLOW_ITEM_WITHOUT_MASK);
	dp_set_ipv6_flow_item(&concrete_patterns[concrete_pattern_cnt++], &ipv6_hdr, proto_id, DP_SET_FLOW_ITEM_WITHOUT_MASK);
	dp_set_end_flow_item(&concrete_patterns[concrete_pattern_cnt++]);

	dp_set_redirect_queue_action(&concrete_actions[concrete_action_cnt++], &queue_action, 0);
	dp_set_end_action(&concrete_actions[concrete_action_cnt++]);

	ret = dp_rte_async_create_concrete_rules(main_eswitch_port->default_async_rules.async_templates.template_tables, DP_ASYNC_RULE_TABLE_DEFAULT,
											concrete_patterns, concrete_actions, DP_ASYNC_RULE_TYPE_DEFAULT_ISOLATION, &flow);
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
	struct dp_port *main_eswitch_port = dp_get_main_eswitch_port();

	if (DP_FAILED(dp_create_concrete_async_default_rule_for_pf(port_id, IPPROTO_IPIP)) ||
			DP_FAILED(dp_create_concrete_async_default_rule_for_pf(port_id, IPPROTO_IPV6))) {
			DPS_LOG_ERR("Failed to install async isolation rules for pf", DP_LOG_PORTID(port_id));
			return DP_ERROR;
	}

	if (DP_FAILED(dp_push_rte_async_flow_rules(main_eswitch_port->port_id))) {
		DPS_LOG_ERR("Failed to above 2 async isolation rules installed on main eswitch port to HW", DP_LOG_PORTID(port_id));
		return DP_ERROR;
	}

	if (DP_FAILED(dp_pull_rte_async_rule_status(main_eswitch_port->port_id, 2))) {
		DPS_LOG_ERR("Failed to pull the status of the above 2 async isolation rules installed on main eswitch port to HW", DP_LOG_PORTID(port_id));
		return DP_ERROR;
	}

	return DP_OK;
}

int dp_destroy_pf_async_isolation_rules(uint16_t port_id)
{
	struct dp_port *port = dp_get_port_by_id(port_id);
	struct dp_port *main_eswitch_port = dp_get_main_eswitch_port();

	for (uint8_t i = 0; i < DP_ASYNC_DEFAULT_FLOW_ON_PF_CNT; i++) {
		struct rte_flow *flow_to_destroy = port->default_async_rules.default_async_flow[i]; // just to be clear on the difference between port/main_eswitch_port in the next function call
		if (DP_FAILED(dp_rte_async_destroy_rule(main_eswitch_port->port_id, flow_to_destroy)))
			DPS_LOG_WARNING("Failed to enqueue the operation of destroying pf async isolation rule", DP_LOG_PORTID(port_id));
	}

	if (DP_FAILED(dp_push_rte_async_flow_rules(main_eswitch_port->port_id))) {
		DPS_LOG_WARNING("Failed to push the operation of destroying above 2 async isolation on main eswitch port to HW", DP_LOG_PORTID(port_id));
		return DP_ERROR;
	}

	if (DP_FAILED(dp_pull_rte_async_rule_status(main_eswitch_port->port_id, 2))) {
		DPS_LOG_ERR("Failed to pull the status of the operation of destroying above 2 async isolation rules on main eswitch port to HW", DP_LOG_PORTID(port_id));
		return DP_ERROR;
	}

	return DP_OK;
}
