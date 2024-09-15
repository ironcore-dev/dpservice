// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#ifndef __INCLUDE_DP_RTE_FLOW_ASYNC_FLOW_PF1_PROXY_H__
#define __INCLUDE_DP_RTE_FLOW_ASYNC_FLOW_PF1_PROXY_H__

#define DP_PF1_PROXY_RULE_COUNT 2

#ifdef __cplusplus
extern "C" {
#endif

#include "dp_port.h"

int dp_create_pf_async_from_proxy_templates(struct dp_port *port);
int dp_create_pf_async_to_proxy_templates(struct dp_port *port);

uint16_t dp_create_pf1_proxy_async_isolation_rules(struct dp_port *port);

#ifdef __cplusplus
}
#endif

#endif
