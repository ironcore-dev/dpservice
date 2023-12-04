// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#ifndef __INCLUDE_DP_MULTI_PATH_H__
#define __INCLUDE_DP_MULTI_PATH_H__

#include <stdint.h>
#include "dp_port.h"

#ifdef __cplusplus
extern "C" {
#endif

void dp_multipath_init(void);

const struct dp_port *dp_multipath_get_pf(uint32_t hash);

#ifdef __cplusplus
}
#endif

#endif
