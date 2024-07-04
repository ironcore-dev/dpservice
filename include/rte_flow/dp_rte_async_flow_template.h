// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#ifndef __INCLUDE_DP_RTE_FLOW_ASYNC_FLOW__TEMPLATE_H__
#define __INCLUDE_DP_RTE_FLOW_ASYNC_FLOW__TEMPLATE_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include <rte_flow.h>
#include "dp_port.h"

int dp_create_pf_async_rte_rule_templates(struct dp_port *port);

#ifdef __cplusplus
}
#endif

#endif
