// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#ifndef __INCLUDE_DP_RTE_FLOW_TRAFFIC_FORWARD_H__
#define __INCLUDE_DP_RTE_FLOW_TRAFFIC_FORWARD_H__

#ifdef __cplusplus
extern "C"
{
#endif

#include <rte_mbuf.h>
#include "dp_mbuf_dyn.h"

int dp_offload_handler(struct rte_mbuf *m, struct dp_flow *df);

#ifdef __cplusplus
}
#endif

#endif
