// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#include "dp_port.h"

#include <rte_flow.h>
#include "rte_flow/dp_rte_async_flow.h"
#include "rte_flow/dp_rte_async_flow_template.h"
#include "rte_flow/dp_rte_flow_helpers.h"


struct dp_port_async_template *dp_alloc_async_template(uint8_t pattern_count, uint8_t actions_count)
{
	struct dp_port_async_template *template;

	template = rte_zmalloc("async_template", sizeof(*template), RTE_CACHE_LINE_SIZE);
	if (!template) {
		DPS_LOG_ERR("Failed to allocate an async flow template");
		return NULL;
	}

	template->pattern_templates = rte_zmalloc("async_template_pattern", sizeof(*template->pattern_templates), RTE_CACHE_LINE_SIZE);
	if (!template->pattern_templates) {
		DPS_LOG_ERR("Failed to allocate an async flow template pattern");
		rte_free(template);
		return NULL;
	}

	template->actions_templates = rte_zmalloc("async_template_actions", sizeof(*template->actions_templates), RTE_CACHE_LINE_SIZE);
	if (!template->actions_templates) {
		DPS_LOG_ERR("Failed to allocate an async flow template actions");
		rte_free(template->pattern_templates);
		rte_free(template);
		return NULL;
	}

	template->pattern_count = pattern_count;
	template->actions_count = actions_count;
	return template;
}

int dp_init_async_template(uint16_t port_id, struct dp_port_async_template *template)
{
	struct rte_flow_error error;

	for (uint8_t i = 0; i < template->pattern_count; ++i) {
		if (!template->pattern_templates[i]) {
			DPS_LOG_ERR("Incomplete async template patterns");
			return DP_ERROR;
		}
	}
	for (uint8_t i = 0; i < template->actions_count; ++i) {
		if (!template->actions_templates[i]) {
			DPS_LOG_ERR("Incomplete async template actions");
			return DP_ERROR;
		}
	}

	template->template_table = rte_flow_template_table_create(port_id, template->table_attr,
															  template->pattern_templates, template->pattern_count,
															  template->actions_templates, template->actions_count,
															  &error);
	if (!template->template_table) {
		DPS_LOG_ERR("Failed to create async flow template table",
					DP_LOG_RET(rte_errno), DP_LOG_PORTID(port_id), DP_LOG_FLOW_ERROR(error.message));
		return DP_ERROR;
	}

	return DP_OK;
}

void dp_destroy_async_template(uint16_t port_id, struct dp_port_async_template *template)
{
	struct rte_flow_error error;
	int ret;

	if (!template)
		return;

	if (template->template_table) {
		ret = rte_flow_template_table_destroy(port_id, template->template_table, &error);
		if (DP_FAILED(ret))
			DPS_LOG_ERR("Failed to destroy async template table", DP_LOG_RET(ret), DP_LOG_PORTID(port_id), DP_LOG_FLOW_ERROR(error.message));
	}
	for (uint8_t i = 0; i < template->actions_count; ++i) {
		if (template->actions_templates[i]) {
			ret = rte_flow_actions_template_destroy(port_id, template->actions_templates[i], &error);
			if (DP_FAILED(ret))
				DPS_LOG_ERR("Failed to destroy async actions template", DP_LOG_RET(ret), DP_LOG_PORTID(port_id), DP_LOG_FLOW_ERROR(error.message));
		}
	}
	for (uint8_t i = 0; i < template->pattern_count; ++i) {
		if (template->pattern_templates[i]) {
			ret = rte_flow_pattern_template_destroy(port_id, template->pattern_templates[i], &error);
			if (DP_FAILED(ret))
				DPS_LOG_ERR("Failed to destroy async pattern template", DP_LOG_RET(ret), DP_LOG_PORTID(port_id), DP_LOG_FLOW_ERROR(error.message));
		}
	}
	rte_free(template->actions_templates);
	rte_free(template->pattern_templates);
	rte_free(template);
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
