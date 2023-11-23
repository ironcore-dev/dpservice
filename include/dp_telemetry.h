// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#ifndef _DP_TELEMETRY_H_
#define _DP_TELEMETRY_H_

#include "dp_nat.h"

#ifdef __cplusplus
extern "C" {
#endif

int dp_telemetry_init(void);
void dp_telemetry_free(void);

int dp_telemetry_register_htable(const struct rte_hash *htable, const char name[RTE_HASH_NAMESIZE], int capacity);

#ifdef __cplusplus
}
#endif

#endif
