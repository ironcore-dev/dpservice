// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#ifndef __INCLUDE_DP_RTE_FLOW_INIT_H__
#define __INCLUDE_DP_RTE_FLOW_INIT_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include <rte_flow.h>
#include "dp_port.h"

int dp_install_isolated_mode_ipip(uint16_t port_id, uint8_t proto_id);

#ifdef ENABLE_VIRTSVC
int dp_install_isolated_mode_virtsvc(uint16_t port_id, uint8_t proto_id, const union dp_ipv6 *svc_ipv6, uint16_t svc_port);
#endif

#ifdef __cplusplus
}
#endif

#endif
