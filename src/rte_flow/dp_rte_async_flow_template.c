// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#include "dp_port.h"

#include "rte_flow/dp_rte_async_flow.h"
#include "rte_flow/dp_rte_async_flow_template.h"
#include "rte_flow/dp_rte_flow_helpers.h"

// TODO names
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

static const struct rte_flow_item pf_isolation_pattern[] = {
	{	.type = RTE_FLOW_ITEM_TYPE_ETH,
		.mask = &dp_flow_item_eth_mask,
	},
	{	.type = RTE_FLOW_ITEM_TYPE_IPV6,
		.mask = &dp_flow_item_ipv6_mask,
	},
	{	.type = RTE_FLOW_ITEM_TYPE_END,
	},
};

static const struct rte_flow_action pf_isolation_action[] = {
	{	.type = RTE_FLOW_ACTION_TYPE_QUEUE, },
	{	.type = RTE_FLOW_ACTION_TYPE_END, },
};

static int dp_create_pf_default_async_rule_templates(uint16_t port_id) {

	int ret;

	// TODO change the aPI to pass port + template pointer
	// TODO change call to || variant with freeup at the end
	ret = dp_rte_async_create_pattern_template(port_id, pf_isolation_pattern, &default_pattern_template_attr,
										DP_ASYNC_TEMPLATE_TABLE_PF_ISOLATION, DP_ASYNC_TEMPLATE_PATTERN_PF_IPV6_PROTO);
	if (DP_FAILED(ret))
		return DP_ERROR;

	ret = dp_rte_async_create_actions_template(port_id, pf_isolation_action, pf_isolation_action, &default_actions_template_attr,
										DP_ASYNC_TEMPLATE_TABLE_PF_ISOLATION, DP_ASYNC_TEMPLATE_ACTION_PF_QUEUE);
	if (DP_FAILED(ret))
		return DP_ERROR;

	// TODO _set_ not _create_?
	dp_rte_async_create_table_attribute(port_id, DP_ASYNC_TEMPLATE_TABLE_PF_ISOLATION, &pf_default_template_table_attr);

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
