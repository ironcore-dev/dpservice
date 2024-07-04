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
#include "dp_port.h"

// TODO move inside
#define DP_ASYNC_FLOW_MAX_AGE_NUM 1024 // tmp value, needs to be investigated what is the maximum one and what consequence it has
#define DP_ASYNC_FLOW_MAX_COUNTER_NUM DP_ASYNC_FLOW_MAX_AGE_NUM // at least equal to the number of used aged action

#define DP_AYNC_FLOW_MAX_FLOW_RULES 64 // it should equal to 1024, which is the maximum number of received pkts in a ring buffer

#define DP_ASYNC_FLOW_TABLE_MAX_RULES 1024 // max number of flow rules an async flow table can hold, too small?
#define DP_ASYNC_FLOW_PF_DEFAULT_TABLE_MAX_RULES 8

#define DP_ASYNC_DEFAULT_OP_QUEUE_ID 0

int dp_port_rte_async_flow_config(uint16_t port_id);
int dp_push_rte_async_flow_rules(uint16_t port_id);
int dp_pull_rte_async_rule_status(uint16_t port_id, uint8_t rule_count);

int dp_rte_async_create_pattern_template(uint16_t port_id,
										const struct rte_flow_item pattern[],
										const struct rte_flow_pattern_template_attr *pattern_template_attr,
										uint8_t table_id, uint8_t pattern_id);

int dp_rte_async_create_actions_template(uint16_t port_id,
										const struct rte_flow_action act[], const struct rte_flow_action msk[],
										const struct rte_flow_actions_template_attr *action_template_attr,
										uint8_t table_id, uint8_t action_id);

void dp_rte_async_create_table_attribute(uint16_t port_id, uint8_t table_id, const struct rte_flow_template_table_attr *attr);

int dp_rte_async_create_table_template(uint16_t port_id, const struct rte_flow_template_table_attr *table_attr,
									struct rte_flow_pattern_template* pattern_templates[], uint8_t nb_pattern_templ,
									struct rte_flow_actions_template* actions_templates[], uint8_t nb_actions_templ,
									struct rte_flow_template_table** template_table);

int dp_rte_async_create_template_tables(struct dp_port *port);

struct rte_flow *dp_rte_flow_async_create(uint16_t port_id,
										  struct rte_flow_template_table *template_table,
										  const struct rte_flow_item *concrete_pattern, uint8_t pattern_template_index,
										  const struct rte_flow_action *concrete_actions, uint8_t action_template_index);

int dp_rte_async_destroy_rule(uint16_t port_id, struct rte_flow *flow);
void dp_rte_async_destroy_templates(uint16_t port_id);

#ifdef __cplusplus
}
#endif

#endif
