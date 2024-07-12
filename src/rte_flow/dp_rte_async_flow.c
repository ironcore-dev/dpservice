// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#include "rte_flow/dp_rte_async_flow.h"

#include <rte_common.h>
#include <rte_malloc.h>

#include "dp_error.h"
#include "dp_log.h"
#include "dpdk_layer.h"
#include "rte_flow/dp_rte_async_flow_template.h"

#define DP_ASYNC_FLOW_MAX_AGE_NUM 1024 // tmp value, needs to be investigated what is the maximum one and what consequence it has
#define DP_ASYNC_FLOW_MAX_COUNTER_NUM DP_ASYNC_FLOW_MAX_AGE_NUM // at least equal to the number of used aged action

#define DP_ASYNC_MAX_FLOW_RULES 64 // it should equal to 1024, which is the maximum number of received pkts in a ring buffer

#define DP_ASYNC_DEFAULT_OP_QUEUE_ID 0

static const struct rte_flow_queue_attr queue_attr = {
	.size = DP_ASYNC_MAX_FLOW_RULES,
};

static const struct rte_flow_op_attr postponed_op_attr = {
	.postpone = 1
};

int dp_configure_async_flows(uint16_t port_id)
{
	static const struct rte_flow_port_attr port_attr = {
		.nb_aging_objects = DP_ASYNC_FLOW_MAX_AGE_NUM,
		.nb_counters = DP_ASYNC_FLOW_MAX_COUNTER_NUM,
	};
	const struct rte_flow_queue_attr *attr_list[DP_NR_STD_RX_QUEUES];
	struct rte_flow_error error;
	int ret;

	for (uint16_t std_queue = 0; std_queue < DP_NR_STD_RX_QUEUES; std_queue++)
		attr_list[std_queue] = &queue_attr;

	ret = rte_flow_configure(port_id, &port_attr, DP_NR_STD_RX_QUEUES, attr_list, &error);
	if (DP_FAILED(ret))
		DPS_LOG_ERR("Failed to configure port's queue attr for async flow operations",
					DP_LOG_PORTID(port_id), DP_LOG_RET(ret), DP_LOG_FLOW_ERROR(error.message));

	return ret;
}

int dp_blocking_commit_async_rules(uint16_t port_id, uint16_t rule_count)
{
	struct rte_flow_op_result results[DP_ASYNC_MAX_FLOW_RULES];
	uint16_t pulled = 0;
	struct rte_flow_error error;
	int ret;

	if (rule_count == 0)
		return DP_OK;

	ret = rte_flow_push(port_id, DP_ASYNC_DEFAULT_OP_QUEUE_ID, &error);
	if (DP_FAILED(ret)) {
		DPS_LOG_ERR("Failed to push rte async flow rules",
					DP_LOG_PORTID(port_id), DP_LOG_RET(ret), DP_LOG_FLOW_ERROR(error.message));
		return ret;
	}

	// Blocking approach - only usable for initialization
	while (pulled < rule_count) {
		ret = rte_flow_pull(port_id, DP_ASYNC_DEFAULT_OP_QUEUE_ID, results, rule_count, &error);
		if (DP_FAILED(ret)) {
			DPS_LOG_ERR("Failed to poll rte async rule status",
						DP_LOG_PORTID(port_id), DP_LOG_RET(ret), DP_LOG_FLOW_ERROR(error.message));
			return DP_ERROR;
		}

		for (int i = 0; i < ret; ++i) {
			if (results[i].status == RTE_FLOW_OP_SUCCESS) {
				pulled++;
			} else {
				DPS_LOG_ERR("Error processing rule", DP_LOG_VALUE(i), DP_LOG_PORTID(port_id));
				return DP_ERROR;
			}
		}
	}

	return DP_OK;
}

struct rte_flow *dp_create_async_rule(uint16_t port_id,
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

	return dp_blocking_commit_async_rules(port_id, destroyed);
}
