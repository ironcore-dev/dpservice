// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#ifndef __INCLUDE_DP_CNTRACK_H__
#define __INCLUDE_DP_CNTRACK_H__

#include <rte_mbuf.h>

#include "dp_flow.h"
#include "dp_mbuf_dyn.h"

#ifdef __cplusplus
extern "C" {
#endif

void dp_cntrack_init(void);

int dp_cntrack_handle(struct rte_mbuf *m, struct dp_flow *df);

void dp_cntrack_flush_cache(void);

struct flow_value *flow_table_insert_sync_nat_entry(const struct flow_key *key, uint32_t nat_ip, uint16_t nat_port, uint16_t port_id);

#ifdef __cplusplus
}
#endif

#endif // __INCLUDE_DP_CNTRACK_H__
