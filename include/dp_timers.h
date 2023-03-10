#ifndef _DP_TIMERS_H_
#define _DP_TIMERS_H_

#include <rte_timer.h>
#include <rte_cycles.h>

#include "dp_error.h"

#ifdef __cplusplus
extern "C" {
#endif

// all times in seconds
#define TIMER_MESSAGE_INTERVAL 5 // increase frequency to check flow table
#define TIMER_DP_MAINTAINANCE_INTERVAL 30
// make sure that we do not sleep (and do stuff) longer than the manage interval
// that would make the code miss it (see main_core_loop())
#define TIMER_MANAGE_INTERVAL 1

void dp_timers_free();
int dp_timers_init();
uint64_t dp_get_rte_timer_resolution();
uint64_t dp_get_timer_manage_interval();

#ifdef __cplusplus
}
#endif
#endif
