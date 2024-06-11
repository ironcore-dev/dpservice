// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#include "dp_port.h"

#include "rte_flow/dp_rte_async_flow.h"
#include "rte_flow/dp_rte_async_flow_template.h"
#include "rte_flow/dp_rte_flow_helpers.h"

static const struct rte_flow_pattern_template_attr default_pattern_template_attr = {
	.ingress = 1
};

static const struct rte_flow_actions_template_attr default_action_template_attr = {
	.ingress = 1
};

static const struct rte_flow_template_table_attr pf_default_table_attr = {
		.flow_attr = {
			.group = 0,
			.ingress = 1,
		},
		.nb_flows = DP_ASYNC_FLOW_PF_DEFAULT_TABLE_MAX_RULES,
		// .specialize = RTE_FLOW_TABLE_SPECIALIZE_TRANSFER_WIRE_ORIG,
};

// static const struct rte_flow_template_table_attr pf_tunnel_table_attr = {
// 		.flow_attr = {
// 			.group = 2,
// 			.transfer = 1,
// 		},
// 		.nb_flows = DP_ASYNC_FLOW_TABLE_MAX_RULES,
// 		.specialize = RTE_FLOW_TABLE_SPECIALIZE_TRANSFER_WIRE_ORIG,
// }; // this is not used due to the fact that async ipinip is not supported by mellanox yet

static int dp_create_pf_default_async_rule_templates(uint16_t port_id) {

	struct rte_flow_item pattern[3];
	int pattern_cnt = 0;

	struct rte_flow_action action[2];
	struct rte_flow_action action_mask[2];
	int action_cnt = 0;
	int action_mask_cnt = 0;

	struct rte_flow_pattern_template_attr pattern_template_attr = default_pattern_template_attr;
	struct rte_flow_actions_template_attr action_template_attr = default_action_template_attr;
	int ret;

	// create match pattern template: IP in IPv6 tunnel packets by only matching the proto field in ipv6 header
	dp_set_eth_flow_item(&pattern[pattern_cnt++], NULL, 0, DP_SET_FLOW_ITEM_WITH_MASK);
	dp_set_ipv6_flow_item(&pattern[pattern_cnt++], NULL, 0, DP_SET_FLOW_ITEM_WITH_MASK);
	dp_set_end_flow_item(&pattern[pattern_cnt++]);

	ret = dp_rte_async_create_pattern_template(port_id, pattern, &pattern_template_attr,
										DP_ASYNC_TEMPLATE_TABLE_PF_ISOLATION, DP_ASYNC_TEMPLATE_PATTERN_PF_IPV6_PROTO);
	if (DP_FAILED(ret))
		return DP_ERROR;

	// create flow action: allow packets to enter dp-service packet queue
	dp_set_redirect_queue_action(&action[action_cnt++], NULL, 0);
	dp_set_end_action(&action[action_cnt++]);

	dp_set_redirect_queue_action(&action_mask[action_mask_cnt++], NULL, 0);
	dp_set_end_action(&action_mask[action_mask_cnt++]);

	ret = dp_rte_async_create_actions_template(port_id, action, action_mask, &action_template_attr,
										DP_ASYNC_TEMPLATE_TABLE_PF_ISOLATION, DP_ASYNC_TEMPLATE_ACTION_PF_QUEUE);
	if (DP_FAILED(ret))
		return DP_ERROR;

	dp_rte_async_create_table_attribute(port_id, DP_ASYNC_TEMPLATE_TABLE_PF_ISOLATION, &pf_default_table_attr);

	return DP_OK;
}

int dp_create_pf_async_rte_rule_templates(uint16_t port_id) {

	DPS_LOG_INFO("Installing async rule templates", DP_LOG_PORTID(port_id));

	if (DP_FAILED(dp_create_pf_default_async_rule_templates(port_id))) {
		DPS_LOG_ERR("Failed to create pf async rte rule templates", DP_LOG_PORTID(port_id));
		return DP_ERROR;
	}

	// add more template pattern/action combinations in the future

	if (DP_FAILED(dp_rte_async_create_template_tables(port_id))) {
		DPS_LOG_ERR("Failed to create pf async rte rule template table", DP_LOG_PORTID(port_id));
		return DP_ERROR;
	}

	return DP_OK;
}
