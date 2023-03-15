#ifndef _DP_TIMERS_H_
#define _DP_TIMERS_H_

#ifdef __cplusplus
extern "C" {
#endif

int dp_timers_init();
void dp_timers_free();

// NOTE: this can change the value of dp_timers_get_manage_interval_cycles()
int dp_timers_add_stats(rte_timer_cb_t stats_cb);

uint64_t dp_timers_get_manage_interval_cycles();

#ifdef __cplusplus
}
#endif
#endif
