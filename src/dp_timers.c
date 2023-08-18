#include <unistd.h>
#include <rte_timer.h>
#include <rte_cycles.h>
#include "dp_conf.h"
#include "dp_error.h"
#include "dp_log.h"
#include "dp_periodic_msg.h"
#include "dp_timers.h"
#include "dpdk_layer.h"
#include "monitoring/dp_event.h"

// All timer intervals are in seconds:

// how often flow table is checked for timed-out flows
// (as a sampling rate it should be smaller than the actual timeout value)
#define TIMER_FLOW_AGING_INTERVAL 5

// how often to perform network maintenance tasks (ND, GARP, ...)
#define TIMER_DP_MAINTENANCE_INTERVAL 30
#define TIMER_DP_MAINTENANCE_STARTUP_INTERVAL 5
#define TIMER_DP_MAINTENANCE_STARTUP_CYCLES 5

// timer for stats printing
#define TIMER_STATS_INTERVAL 1

static int dp_maintenance_interval = TIMER_DP_MAINTENANCE_STARTUP_INTERVAL;

static struct rte_timer dp_flow_aging_timer;
static struct rte_timer dp_maintenance_timer;
static struct rte_timer dp_stats_timer;
static uint64_t dp_timer_manage_interval_cycles;

static void dp_flow_aging_timer_cb(__rte_unused struct rte_timer *timer, __rte_unused void *arg)
{
	int ret = dp_send_event_flow_aging_msg();

	if (DP_FAILED(ret))
		DPS_LOG_WARNING("Cannot send flow aging event", DP_LOG_RET(ret));
}

static inline void dp_maintenance_timer_cb_core(void)
{
	if (dp_conf_is_ipv6_overlay_enabled()) {
		trigger_nd_ra();
		trigger_nd_unsol_adv();
	}
	trigger_garp();
}

static void dp_maintenance_timer_cb(__rte_unused struct rte_timer *timer, __rte_unused void *arg)
{
	dp_maintenance_timer_cb_core();
}

static void dp_maintenance_startup_timer_cb(struct rte_timer *timer, __rte_unused void *arg)
{
	static unsigned int counter = 0;
	uint64_t cycles;

	dp_maintenance_timer_cb_core();

	// This is a simple back-off of the maintenance timer. Only at the beginning of the timer life time,
	// do it every TIMER_DP_MAINTENANCE_STARTUP_INTERVAL seconds. After TIMER_DP_MAINTENANCE_STARTUP_CYCLES times
	// and dp_maintenance_interval is set to a greater value, reset the timer with the greater value.
	if ((dp_maintenance_interval > TIMER_DP_MAINTENANCE_STARTUP_INTERVAL) && (counter <= TIMER_DP_MAINTENANCE_STARTUP_CYCLES)) {
		counter++;
		if (counter == TIMER_DP_MAINTENANCE_STARTUP_CYCLES) {
			cycles = dp_maintenance_interval * rte_get_timer_hz();
			if (DP_FAILED(rte_timer_reset(timer, cycles, PERIODICAL, rte_lcore_id(), dp_maintenance_timer_cb, NULL)))
				DPS_LOG_ERR("Cannot start maintenance timer");
		}
	}
}

uint64_t dp_timers_get_manage_interval_cycles(void)
{
	return dp_timer_manage_interval_cycles;
}

int dp_timers_get_flow_aging_interval(void)
{
	return TIMER_FLOW_AGING_INTERVAL;
}

static inline int dp_timers_add(struct rte_timer *timer, int period, rte_timer_cb_t callback)
{
	uint64_t cycles = period * rte_get_timer_hz();

	// make sure we manage timers often enough
	if (!dp_timer_manage_interval_cycles || cycles < dp_timer_manage_interval_cycles)
		dp_timer_manage_interval_cycles = cycles;

	rte_timer_init(timer);

	// there is no errno for this call, so log the failure in caller for better call stack
	return rte_timer_reset(timer, cycles, PERIODICAL, rte_lcore_id(), callback, NULL);
}

void dp_timers_signal_initialization(void)
{
	dp_maintenance_interval = TIMER_DP_MAINTENANCE_INTERVAL;
}

int dp_timers_init(void)
{
	int ret;
	int flow_aging_interval = TIMER_FLOW_AGING_INTERVAL;

#ifdef ENABLE_PYTEST
	if (flow_aging_interval > dp_conf_get_flow_timeout())
		flow_aging_interval = dp_conf_get_flow_timeout();
#endif

	ret = rte_timer_subsystem_init();
	if (DP_FAILED(ret)) {
		DPS_LOG_ERR("Cannot init timer subsystem", DP_LOG_RET(ret));
		return ret;
	}

	if (DP_FAILED(dp_timers_add(&dp_flow_aging_timer, flow_aging_interval, dp_flow_aging_timer_cb))) {
		DPS_LOG_ERR("Cannot start flow aging timer");
		return DP_ERROR;
	}

	if (DP_FAILED(dp_timers_add(&dp_maintenance_timer, dp_maintenance_interval, dp_maintenance_startup_timer_cb))) {
		DPS_LOG_ERR("Cannot start maintenance startup timer");
		return DP_ERROR;
	}

	return DP_OK;
}

void dp_timers_free(void)
{
	rte_timer_subsystem_finalize();
}

int dp_timers_add_stats(rte_timer_cb_t stats_cb)
{
	if (DP_FAILED(dp_timers_add(&dp_stats_timer, TIMER_STATS_INTERVAL, stats_cb))) {
		DPS_LOG_ERR("Cannot start stats timer");
		return DP_ERROR;
	}
	return DP_OK;
}
