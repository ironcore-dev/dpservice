// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#ifndef __INCLUDE_DP_RTE_FLOW_ASYNC_FLOW_ISOLATION_H__
#define __INCLUDE_DP_RTE_FLOW_ASYNC_FLOW_ISOLATION_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <rte_flow.h>
#include "dp_ipaddr.h"
#include "dp_port.h"

int dp_create_pf_async_isolation_templates(struct dp_port *port);

int dp_create_pf_async_isolation_rules(struct dp_port *port);

#ifdef ENABLE_VIRTSVC
int dp_create_virtsvc_async_isolation_templates(struct dp_port *port, uint8_t proto_id);

struct rte_flow *dp_create_virtsvc_async_isolation_rule(uint16_t port_id, uint8_t proto_id,
														const union dp_ipv6 *svc_ipv6, rte_be16_t svc_port,
														struct rte_flow_template_table *template_table,
														const union dp_ipv6 *ul_addr);
#endif

#ifdef __cplusplus
}
#endif

#endif
