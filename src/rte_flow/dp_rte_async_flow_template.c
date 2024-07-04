// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#include "dp_port.h"

#include "rte_flow/dp_rte_async_flow.h"
#include "rte_flow/dp_rte_async_flow_template.h"
#include "rte_flow/dp_rte_flow_helpers.h"


int dp_create_async_template(uint16_t port_id, struct dp_port_async_template *template, uint8_t pattern_count, uint8_t actions_count)
{
	struct rte_flow_error error;

	if (pattern_count > RTE_DIM(template->pattern_templates) || actions_count > RTE_DIM(template->actions_templates)) {
		DPS_LOG_ERR("Invalid async template pattern/actions count");
		goto rollback;
	}
	for (uint8_t i = 0; i < pattern_count; ++i) {
		if (!template->pattern_templates[i]) {
			DPS_LOG_ERR("Incomplete async template patterns");
			goto rollback;
		}
	}
	for (uint8_t i = 0; i < actions_count; ++i) {
		if (!template->actions_templates[i]) {
			DPS_LOG_ERR("Incomplete async template actions");
			goto rollback;
		}
	}

	template->template_table = rte_flow_template_table_create(port_id, template->table_attr,
															  template->pattern_templates, pattern_count,
															  template->actions_templates, actions_count,
															  &error);
	if (!template->template_table) {
		DPS_LOG_ERR("Failed to create async flow template table",
					DP_LOG_RET(rte_errno), DP_LOG_PORTID(port_id), DP_LOG_FLOW_ERROR(error.message));
		goto rollback;
	}

	return DP_OK;

rollback:
	dp_destroy_async_template(port_id, template);
	return DP_ERROR;
}

void dp_destroy_async_template(uint16_t port_id, struct dp_port_async_template *template)
{
	struct rte_flow_error error;
	int ret;

	if (template->template_table) {
		ret = rte_flow_template_table_destroy(port_id, template->template_table, &error);
		if (DP_FAILED(ret))
			DPS_LOG_ERR("Failed to destroy async template table", DP_LOG_RET(ret), DP_LOG_PORTID(port_id), DP_LOG_FLOW_ERROR(error.message));
	}
	for (uint8_t i = 0; i < RTE_DIM(template->actions_templates); ++i) {
		if (template->actions_templates[i]) {
			ret = rte_flow_actions_template_destroy(port_id, template->actions_templates[i], &error);
			if (DP_FAILED(ret))
				DPS_LOG_ERR("Failed to destroy async actions template", DP_LOG_RET(ret), DP_LOG_PORTID(port_id), DP_LOG_FLOW_ERROR(error.message));
		}
	}
	for (uint8_t i = 0; i < RTE_DIM(template->pattern_templates); ++i) {
		if (template->pattern_templates[i]) {
			ret = rte_flow_pattern_template_destroy(port_id, template->pattern_templates[i], &error);
			if (DP_FAILED(ret))
				DPS_LOG_ERR("Failed to destroy async pattern template", DP_LOG_RET(ret), DP_LOG_PORTID(port_id), DP_LOG_FLOW_ERROR(error.message));
		}
	}
	memset(template, 0, sizeof(*template));
}


struct rte_flow_pattern_template *dp_create_async_pattern_template(uint16_t port_id,
																   const struct rte_flow_pattern_template_attr *pattern_template_attr,									const struct rte_flow_item pattern[])
{
	struct rte_flow_pattern_template *pattern_template;
	struct rte_flow_error error;

	pattern_template = rte_flow_pattern_template_create(port_id, pattern_template_attr, pattern, &error);
	if (!pattern_template)
		DPS_LOG_ERR("Failed to create async flow pattern template",
					DP_LOG_RET(rte_errno), DP_LOG_PORTID(port_id), DP_LOG_FLOW_ERROR(error.message));

	return pattern_template;
}

struct rte_flow_actions_template *dp_create_async_actions_template(uint16_t port_id,
																   const struct rte_flow_actions_template_attr *actions_template_attr,
																   const struct rte_flow_action actions[],
																   const struct rte_flow_action masks[])
{
	struct rte_flow_actions_template *actions_template;
	struct rte_flow_error error;

	actions_template = rte_flow_actions_template_create(port_id, actions_template_attr, actions, masks, &error);
	if (!actions_template)
		DPS_LOG_ERR("Failed to create async flow action template",
					DP_LOG_RET(rte_errno), DP_LOG_PORTID(port_id), DP_LOG_FLOW_ERROR(error.message));

	return actions_template;
}
