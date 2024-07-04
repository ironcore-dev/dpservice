// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#ifndef __INCLUDE_DP_RTE_FLOW_ASYNC_FLOW_H__
#define __INCLUDE_DP_RTE_FLOW_ASYNC_FLOW_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include <rte_flow.h>

// TODO move inside
#define DP_ASYNC_FLOW_MAX_AGE_NUM 1024 // tmp value, needs to be investigated what is the maximum one and what consequence it has
#define DP_ASYNC_FLOW_MAX_COUNTER_NUM DP_ASYNC_FLOW_MAX_AGE_NUM // at least equal to the number of used aged action

#define DP_AYNC_FLOW_MAX_FLOW_RULES 64 // it should equal to 1024, which is the maximum number of received pkts in a ring buffer

#define DP_ASYNC_FLOW_TABLE_MAX_RULES 1024 // max number of flow rules an async flow table can hold, too small?
#define DP_ASYNC_FLOW_PF_DEFAULT_TABLE_MAX_RULES 8

#define DP_ASYNC_DEFAULT_OP_QUEUE_ID 0

// TODO dp_port_ in wrong file
int dp_port_rte_async_flow_config(uint16_t port_id);

int dp_commit_rte_async_flow_rules(uint16_t port_id, uint16_t rule_count);

struct rte_flow *dp_rte_flow_async_create(uint16_t port_id,
										  struct rte_flow_template_table *template_table,
										  const struct rte_flow_item *concrete_pattern, uint8_t pattern_template_index,
										  const struct rte_flow_action *concrete_actions, uint8_t action_template_index);

int dp_destroy_async_rules(uint16_t port_id, struct rte_flow *rules[], size_t rule_count);

#ifdef __cplusplus
}
#endif

#endif
