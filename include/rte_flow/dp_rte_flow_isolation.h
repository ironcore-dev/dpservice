// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#ifndef __INCLUDE_DP_RTE_FLOW_ISOLATION_H__
#define __INCLUDE_DP_RTE_FLOW_ISOLATION_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

int dp_install_isolated_mode(uint16_t port_id);

#ifdef __cplusplus
}
#endif

#endif
