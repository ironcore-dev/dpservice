// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#ifndef __INCLUDE_DP_PERIODIC_MSG_H__
#define __INCLUDE_DP_PERIODIC_MSG_H__

#include "dpdk_layer.h"
#include "dp_mbuf_dyn.h"

#ifdef __cplusplus
extern "C" {
#endif

void send_to_all_vfs(const struct rte_mbuf *pkt, uint16_t eth_type);
void trigger_garp(void);
void trigger_nd_unsol_adv(void);
void trigger_nd_ra(void);

#ifdef __cplusplus
}
#endif
#endif
