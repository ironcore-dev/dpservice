// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#ifndef __INCLUDE_DP_MAGLEV_H__
#define __INCLUDE_DP_MAGLEV_H__

#ifdef __cplusplus
extern "C" {
#endif
#include <stdint.h>
#include "dp_util.h"
#include "dp_lb.h"

int dp_delete_maglev_backend(struct lb_value *lbval, const uint8_t *delete_server);
int dp_add_maglev_backend(struct lb_value *lbval, const uint8_t *new_server);

#ifdef __cplusplus
}
#endif
#endif