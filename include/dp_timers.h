#ifndef _DP_TIMERS_H_
#define _DP_TIMERS_H_

#ifdef __cplusplus
extern "C" {
#endif

int dp_timers_init();
void dp_timers_free();

uint64_t dp_timers_get_manage_interval();

#ifdef __cplusplus
}
#endif
#endif
