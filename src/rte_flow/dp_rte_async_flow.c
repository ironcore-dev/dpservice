// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#include <rte_common.h>
#include <rte_malloc.h>

#include "rte_flow/dp_rte_async_flow.h"
#include "dpdk_layer.h"
#include "dp_port.h"

static struct rte_flow_queue_attr queue_attr = {
												.size = DP_AYNC_FLOW_MAX_FLOW_RULES,
											};

static const struct rte_flow_op_attr op_attr = {1};

int dp_port_rte_async_flow_config(uint16_t port_id)
{
	struct rte_flow_error error;
	int ret;
	
	struct rte_flow_port_attr port_attr = {
		.nb_aging_objects = DP_ASYNC_FLOW_MAX_AGE_NUM,
		.nb_counters = DP_ASYNC_FLOW_MAX_COUNTER_NUM,
	};

	const struct rte_flow_queue_attr *attr_list[DP_NR_STD_RX_QUEUES];

	for (uint16_t std_queue = 0; std_queue < DP_NR_STD_RX_QUEUES; std_queue++)
		attr_list[std_queue] = &queue_attr;
	
	ret = rte_flow_configure(port_id, &port_attr, DP_NR_STD_RX_QUEUES, attr_list, &error);
	if (DP_FAILED(ret)){
		DPS_LOG_ERR("Failed to configure port's queue attr for async flow operations",
						DP_LOG_PORTID(port_id), DP_LOG_FLOW_ERROR(error.message), DP_LOG_RET(ret));
		return DP_ERROR;
	}
	return DP_OK;
}

int dp_push_rte_async_flow_rules(uint16_t port_id)
{

	struct rte_flow_error error;

	int ret = rte_flow_push(port_id, 0, &error); // std queue is always 0 in our case
	if (DP_FAILED(ret)) {
		DPS_LOG_ERR("Failed to push rte async flow rules",
						DP_LOG_PORTID(port_id), DP_LOG_FLOW_ERROR(error.message), DP_LOG_RET(ret));
		return DP_ERROR;
	}
	return DP_OK;
}

int dp_pull_rte_async_rule_status(uint16_t port_id, uint8_t rule_count)
{
	struct rte_flow_op_result *res;
	int success = 0;
	struct rte_flow_error error;
	int ret;

	res = rte_zmalloc("flow_op_res", sizeof(struct rte_flow_op_result) * DP_AYNC_FLOW_MAX_FLOW_RULES, RTE_CACHE_LINE_SIZE);

	// TODO: to avoid endless loop due to failed flow rule installation, it is needed to improve pulling mechanism.
	while (success < rule_count) {
		ret = rte_flow_pull(port_id, 0, res,
					rule_count, &error);
		
		if (DP_FAILED(ret)) {
			DPS_LOG_ERR("Failed to poll rte async rule status",
						DP_LOG_PORTID(port_id), DP_LOG_FLOW_ERROR(error.message), DP_LOG_RET(ret));
			rte_free(res);
			return DP_ERROR;
		}

		for (int i = 0; i < ret; i++) {
			if (res[i].status == RTE_FLOW_OP_SUCCESS) {
				success++;
			}

			if (res[i].user_data) {
				DPS_LOG_WARNING("Non empty user data when p", DP_LOG_PORTID(port_id));
			}
		}
	}
	rte_free(res);
	return DP_OK;
}

int dp_rte_async_create_pattern_template(uint16_t port_id,
										const struct rte_flow_item pattern[],
										const struct rte_flow_pattern_template_attr *pattern_template_attr,
										uint8_t table_id, uint8_t pattern_id)
{
	struct rte_flow_pattern_template *pattern_template;
	struct rte_flow_error error;
	struct dp_port *port = dp_get_port_by_id(port_id);

	pattern_template = rte_flow_pattern_template_create(port_id, pattern_template_attr, pattern, &error);

	if (!pattern_template){
		DPS_LOG_ERR("Failed to create async flow pattern template",
						DP_LOG_PORTID(port_id), DP_LOG_FLOW_ERROR(error.message));
		return DP_ERROR;
	}
	port->default_async_rules.async_templates[table_id].pattern_templates[pattern_id] = pattern_template;
	port->default_async_rules.async_templates[table_id].nr_patterns++;
	return DP_OK;
}

int dp_rte_async_create_actions_template(uint16_t port_id,
										const struct rte_flow_action act[], const struct rte_flow_action msk[],
										const struct rte_flow_actions_template_attr *action_template_attr,
										uint8_t table_id, uint8_t action_id)
{
	struct rte_flow_actions_template *actions_template;
	struct rte_flow_error error;
	struct dp_port *port = dp_get_port_by_id(port_id);

	actions_template =
			rte_flow_actions_template_create(port_id, action_template_attr, act, msk, &error);
	if (!actions_template){
		DPS_LOG_ERR("Failed to create async flow action template",
						DP_LOG_PORTID(port_id), DP_LOG_FLOW_ERROR(error.message));
		return DP_ERROR;
	}

	port->default_async_rules.async_templates[table_id].action_templates[action_id] = actions_template;
	port->default_async_rules.async_templates[table_id].nr_actions++;
	return DP_OK;
}

void dp_rte_async_create_table_attribute(uint16_t port_id, uint8_t table_id, const struct rte_flow_template_table_attr *attr)
{
	struct dp_port *port = dp_get_port_by_id(port_id);
	port->default_async_rules.async_templates[table_id].table_attr = attr;
	port->default_async_rules.async_templates[table_id].filled = true;
}

int dp_rte_async_create_table_template(uint16_t port_id, const struct rte_flow_template_table_attr *table_attr,
													struct rte_flow_pattern_template* pattern_templates[], uint8_t nb_pattern_templ,
													struct rte_flow_actions_template* actions_templates[], uint8_t nb_actions_templ,
													struct rte_flow_template_table** template_table)
{
    struct rte_flow_error error;
	struct rte_flow_template_table *table;
	
	table = rte_flow_template_table_create(port_id, table_attr, pattern_templates, nb_pattern_templ, actions_templates, nb_actions_templ, &error);
	
	if (!table){
		DPS_LOG_ERR("Failed to create async flow table template",
						DP_LOG_PORTID(port_id), DP_LOG_FLOW_ERROR(error.message));
		return DP_ERROR;
	}
	
	*template_table = table;
	return DP_OK;
}


int dp_rte_async_create_template_tables(uint16_t port_id)
{

	int ret;
	struct dp_port* port = dp_get_port_by_id(port_id);
	struct dp_port_rte_async_template *template;

	// the current approach is that each template table is initialized with all patterns/actions for pf/vf
	// choose the correct pattern/action by using dp_rte_async_rule_type_index when concretizing flow rules
	// assuming the attributes of patterns/actions match with table attributes
	for (int i = 0; i < DP_ASYNC_TEMPLATE_MAX_TABLE; i++ ) {
		 template = &port->default_async_rules.async_templates[i];
		if (!template->filled)
			continue; // or break assuming there is no skipped template
		
		ret = dp_rte_async_create_table_template(port->port_id, template->table_attr,
											template->pattern_templates, template->nr_patterns,
											template->action_templates, template->nr_actions,
											&(template->template_table));
		if (DP_FAILED(ret)) {
			DPS_LOG_ERR("Failed to create async flow rule table", DP_LOG_VALUE(i));
			return DP_ERROR;
		}
	}
	return DP_OK;
}

int dp_rte_async_create_concrete_rules(uint16_t port_id,
									struct rte_flow_template_table *template_table,
									struct rte_flow_item *concrete_patterns, struct rte_flow_action *concrete_actions,
									uint8_t used_pattern_index, uint8_t used_action_index,
									struct rte_flow **flow)
{
	struct rte_flow *created_flow;
	struct rte_flow_error error;
	
	created_flow = rte_flow_async_create(port_id, 0, &op_attr, template_table,
			concrete_patterns, used_pattern_index, concrete_actions, used_action_index, NULL, &error);

	if (!created_flow) {
		DPS_LOG_ERR("Concrete flow rule cannot be created", DP_LOG_PORTID(port_id), DP_LOG_FLOW_ERROR(error.message));
		return DP_ERROR;
	}

	*flow = created_flow;
	return DP_OK;
}

int dp_rte_async_destroy_rule(uint16_t port_id, struct rte_flow *flow)
{
	uint32_t queue_id = DP_ASYNC_DEFAULT_OP_QUEUE_ID;
	struct rte_flow_error error;
	int ret;
	const struct rte_flow_op_attr op_no_delay_attr = {1};


	ret = rte_flow_async_destroy(port_id, queue_id, &op_no_delay_attr, flow, NULL, &error);
	if (DP_FAILED(ret)){
		DPS_LOG_ERR("Concrete flow rule cannot be destroyed", DP_LOG_PORTID(port_id), DP_LOG_FLOW_ERROR(error.message));
		return DP_ERROR;
	}
	return DP_OK;
}

static void dp_rte_async_destroy_pattern_template(struct dp_port *port, uint8_t table_id)
{
	struct rte_flow_error error;
	int ret;
	
	for (uint8_t i = 0; i < port->default_async_rules.async_templates[table_id].nr_patterns; i++) {
		ret = rte_flow_pattern_template_destroy(port->port_id, port->default_async_rules.async_templates[table_id].pattern_templates[i], &error);
		if (DP_FAILED(ret))
			DPS_LOG_WARNING("Failed to destroy pattern template", DP_LOG_PORTID(port->port_id), DP_LOG_FLOW_ERROR(error.message));
	}

}


static void dp_rte_async_destroy_action_template(struct dp_port *port, uint8_t table_id)
{
	struct rte_flow_error error;
	int ret = DP_OK;

	for (uint8_t i = 0; i < port->default_async_rules.async_templates[table_id].nr_actions; i++) {
		ret = rte_flow_actions_template_destroy(port->port_id, port->default_async_rules.async_templates[table_id].action_templates[i], &error);
		if (DP_FAILED(ret))
			DPS_LOG_WARNING("Failed to destroy action template", DP_LOG_PORTID(port->port_id), DP_LOG_FLOW_ERROR(error.message));
	}
}


static void dp_rte_async_destroy_table_template(struct dp_port *port, uint8_t table_id)
{
	struct rte_flow_error error;
	int ret;
	
	ret = rte_flow_template_table_destroy(port->port_id, port->default_async_rules.async_templates[table_id].template_table, &error);
	if (DP_FAILED(ret))
		DPS_LOG_WARNING("Failed to destroy template table", DP_LOG_PORTID(port->port_id), DP_LOG_FLOW_ERROR(error.message));
}


void dp_rte_async_destroy_templates(uint16_t port_id)
{
	struct dp_port *port = dp_get_port_by_id(port_id);
	
	for (uint8_t i = 0; i < DP_ASYNC_TEMPLATE_MAX_TABLE; i++) {
		dp_rte_async_destroy_table_template(port, i); // destroy table template first, then destroy pattern and action template
		dp_rte_async_destroy_pattern_template(port, i);
		dp_rte_async_destroy_action_template(port, i);
	}	
}
