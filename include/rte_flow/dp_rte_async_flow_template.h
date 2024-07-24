// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#ifndef __INCLUDE_DP_RTE_ASYNC_FLOW_TEMPLATE_H__
#define __INCLUDE_DP_RTE_ASYNC_FLOW_TEMPLATE_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <rte_flow.h>

struct dp_port_async_template *dp_alloc_async_template(uint8_t pattern_count, uint8_t actions_count);
int dp_init_async_template(uint16_t port_id, struct dp_port_async_template *tmpl);
void dp_destroy_async_template(uint16_t port_id, struct dp_port_async_template *tmpl);

struct rte_flow_pattern_template
*dp_create_async_pattern_template(uint16_t port_id,
								const struct rte_flow_pattern_template_attr *pattern_template_attr,
								const struct rte_flow_item pattern[]);

struct rte_flow_actions_template
*dp_create_async_actions_template(uint16_t port_id,
								const struct rte_flow_actions_template_attr *actions_template_attr,
								const struct rte_flow_action actions[],
								const struct rte_flow_action masks[]);

#ifdef __cplusplus
}
#endif

#endif
