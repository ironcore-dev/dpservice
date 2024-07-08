// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#include "rte_flow/dp_rte_async_flow.h"

#include <rte_common.h>
#include <rte_malloc.h>

#include "dpdk_layer.h"
#include "rte_flow/dp_rte_async_flow_template.h"


static struct rte_flow_queue_attr queue_attr = {
												.size = DP_AYNC_FLOW_MAX_FLOW_RULES,
											};

static const struct rte_flow_op_attr postponed_op_attr = {
	.postpone = 1
};

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

static int dp_push_rte_async_flow_rules(uint16_t port_id)
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

static int dp_pull_rte_async_rule_status(uint16_t port_id, uint16_t rule_count)
{
	struct rte_flow_op_result *res;
	uint16_t pulled = 0;
	struct rte_flow_error error;
	int ret;

	res = rte_zmalloc("flow_op_res", sizeof(struct rte_flow_op_result) * DP_AYNC_FLOW_MAX_FLOW_RULES, RTE_CACHE_LINE_SIZE);

	// TODO: to avoid endless loop due to failed flow rule installation, it is needed to improve pulling mechanism.
	while (pulled < rule_count) {
		ret = rte_flow_pull(port_id, 0, res,
					rule_count, &error);
		
		if (DP_FAILED(ret)) {
			DPS_LOG_ERR("Failed to poll rte async rule status",
						DP_LOG_PORTID(port_id), DP_LOG_FLOW_ERROR(error.message), DP_LOG_RET(ret));
			rte_free(res);
			return DP_ERROR;
		}

		for (int i = 0; i < ret; i++) {
			if (res[i].user_data) {
				DPS_LOG_WARNING("Non empty user data when p", DP_LOG_PORTID(port_id));
			}
			if (res[i].status == RTE_FLOW_OP_SUCCESS) {
				pulled++;
			} else {
				DPS_LOG_ERR("Error processing rule", DP_LOG_PORTID(port_id), DP_LOG_VALUE(i));
				rte_free(res);
				return DP_ERROR;
			}
		}
	}
	rte_free(res);
	return DP_OK;
}

// TODO maybe hide thw two and make them inline
// TODO rename to indicate the fact that this is BLOCKING INDEFINITELY!
int dp_commit_rte_async_flow_rules(uint16_t port_id, uint16_t rule_count)
{
	if (rule_count == 0)
		return DP_OK;

	if (DP_FAILED(dp_push_rte_async_flow_rules(port_id)))
		return DP_ERROR;

	return dp_pull_rte_async_rule_status(port_id, rule_count);
}

struct rte_flow *dp_rte_flow_async_create(uint16_t port_id,
										  struct rte_flow_template_table *template_table,
										  const struct rte_flow_item *concrete_pattern, uint8_t pattern_template_index,
										  const struct rte_flow_action *concrete_actions, uint8_t action_template_index)
{
	struct rte_flow *created_flow;
	struct rte_flow_error error;

	created_flow = rte_flow_async_create(port_id, 0, &postponed_op_attr, template_table,
										 concrete_pattern, pattern_template_index, concrete_actions, action_template_index,
										 NULL, &error);
	if (!created_flow)
		DPS_LOG_ERR("Concrete flow rule cannot be created", DP_LOG_RET(rte_errno), DP_LOG_PORTID(port_id), DP_LOG_FLOW_ERROR(error.message));

	return created_flow;
}

int dp_destroy_async_rules(uint16_t port_id, struct rte_flow *rules[], size_t rule_count)
{
	struct rte_flow_error error;
	uint16_t destroyed = 0;
	int ret;

	for (uint8_t i = 0; i < rule_count; ++i) {
		if (!rules[i])
			continue;

		ret = rte_flow_async_destroy(port_id, DP_ASYNC_DEFAULT_OP_QUEUE_ID, &postponed_op_attr, rules[i], NULL, &error);
		if (DP_FAILED(ret))
			DPS_LOG_ERR("Cannot destroy async flow rule", DP_LOG_RET(ret), DP_LOG_PORTID(port_id), DP_LOG_FLOW_ERROR(error.message));
		else {
			destroyed++;
			rules[i] = NULL;
		}
	}

	return dp_commit_rte_async_flow_rules(port_id, destroyed);
}
