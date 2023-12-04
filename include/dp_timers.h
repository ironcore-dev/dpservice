// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#ifndef _DP_TIMERS_H_
#define _DP_TIMERS_H_

#include <rte_timer.h>

#ifdef __cplusplus
extern "C" {
#endif

int dp_timers_init(void);
void dp_timers_free(void);

// NOTE: this can change the value of dp_timers_get_manage_interval_cycles()
int dp_timers_add_stats(rte_timer_cb_t stats_cb);

uint64_t dp_timers_get_manage_interval_cycles(void);
uint8_t dp_timers_get_flow_aging_interval(void);
void dp_timers_signal_initialization(void);

#ifdef __cplusplus
}
#endif
#endif
