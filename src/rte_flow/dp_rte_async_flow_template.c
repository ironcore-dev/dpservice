// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#include "rte_flow/dp_rte_async_flow_template.h"

#include <rte_flow.h>

#include "dp_port.h"
#include "rte_flow/dp_rte_async_flow.h"
#include "rte_flow/dp_rte_flow_helpers.h"


struct dp_port_async_template *dp_alloc_async_template(uint8_t pattern_count, uint8_t actions_count)
{
	struct dp_port_async_template *tmpl;

	tmpl = rte_zmalloc("async_template", sizeof(*tmpl), RTE_CACHE_LINE_SIZE);
	if (!tmpl) {
		DPS_LOG_ERR("Failed to allocate an async flow template");
		return NULL;
	}

	tmpl->pattern_templates = rte_zmalloc("async_template_pattern", sizeof(*tmpl->pattern_templates), RTE_CACHE_LINE_SIZE);
	if (!tmpl->pattern_templates) {
		DPS_LOG_ERR("Failed to allocate an async flow template pattern");
		rte_free(tmpl);
		return NULL;
	}

	tmpl->actions_templates = rte_zmalloc("async_template_actions", sizeof(*tmpl->actions_templates), RTE_CACHE_LINE_SIZE);
	if (!tmpl->actions_templates) {
		DPS_LOG_ERR("Failed to allocate an async flow template actions");
		rte_free(tmpl->pattern_templates);
		rte_free(tmpl);
		return NULL;
	}

	tmpl->pattern_count = pattern_count;
	tmpl->actions_count = actions_count;
	return tmpl;
}

int dp_init_async_template(uint16_t port_id, struct dp_port_async_template *tmpl)
{
	struct rte_flow_error error;

	for (uint8_t i = 0; i < tmpl->pattern_count; ++i) {
		if (!tmpl->pattern_templates[i]) {
			DPS_LOG_ERR("Incomplete async template patterns");
			return DP_ERROR;
		}
	}
	for (uint8_t i = 0; i < tmpl->actions_count; ++i) {
		if (!tmpl->actions_templates[i]) {
			DPS_LOG_ERR("Incomplete async template actions");
			return DP_ERROR;
		}
	}

	tmpl->template_table = rte_flow_template_table_create(port_id, tmpl->table_attr,
															  tmpl->pattern_templates, tmpl->pattern_count,
															  tmpl->actions_templates, tmpl->actions_count,
															  &error);
	if (!tmpl->template_table) {
		DPS_LOG_ERR("Failed to create async flow template table",
					DP_LOG_RET(rte_errno), DP_LOG_PORTID(port_id), DP_LOG_FLOW_ERROR(error.message));
		return DP_ERROR;
	}

	return DP_OK;
}

void dp_destroy_async_template(uint16_t port_id, struct dp_port_async_template *tmpl)
{
	struct rte_flow_error error;
	int ret;

	if (!tmpl)
		return;

	if (tmpl->template_table) {
		ret = rte_flow_template_table_destroy(port_id, tmpl->template_table, &error);
		if (DP_FAILED(ret))
			DPS_LOG_ERR("Failed to destroy async template table", DP_LOG_RET(ret), DP_LOG_PORTID(port_id), DP_LOG_FLOW_ERROR(error.message));
	}
	for (uint8_t i = 0; i < tmpl->actions_count; ++i) {
		if (tmpl->actions_templates[i]) {
			ret = rte_flow_actions_template_destroy(port_id, tmpl->actions_templates[i], &error);
			if (DP_FAILED(ret))
				DPS_LOG_ERR("Failed to destroy async actions template", DP_LOG_RET(ret), DP_LOG_PORTID(port_id), DP_LOG_FLOW_ERROR(error.message));
		}
	}
	for (uint8_t i = 0; i < tmpl->pattern_count; ++i) {
		if (tmpl->pattern_templates[i]) {
			ret = rte_flow_pattern_template_destroy(port_id, tmpl->pattern_templates[i], &error);
			if (DP_FAILED(ret))
				DPS_LOG_ERR("Failed to destroy async pattern template", DP_LOG_RET(ret), DP_LOG_PORTID(port_id), DP_LOG_FLOW_ERROR(error.message));
		}
	}
	rte_free(tmpl->actions_templates);
	rte_free(tmpl->pattern_templates);
	rte_free(tmpl);
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
