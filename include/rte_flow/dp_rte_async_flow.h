// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#ifndef __INCLUDE_DP_RTE_FLOW_ASYNC_FLOW_H__
#define __INCLUDE_DP_RTE_FLOW_ASYNC_FLOW_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <rte_flow.h>

int dp_configure_async_flows(uint16_t port_id);

/* WARNING this is a busy-loop blocking implementation. Only use during initialization! */
int dp_blocking_commit_async_rules(uint16_t port_id, uint16_t rule_count);

struct rte_flow *dp_create_async_rule(uint16_t port_id,
										  struct rte_flow_template_table *template_table,
										  const struct rte_flow_item *concrete_pattern, uint8_t pattern_template_index,
										  const struct rte_flow_action *concrete_actions, uint8_t action_template_index);

int dp_destroy_async_rules(uint16_t port_id, struct rte_flow *rules[], size_t rule_count);

#ifdef __cplusplus
}
#endif

#endif
