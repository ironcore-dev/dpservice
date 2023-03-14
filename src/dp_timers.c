#include <unistd.h>
#include <rte_timer.h>
#include <rte_cycles.h>
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

// timer for stats printing
#define TIMER_STATS_INTERVAL 1


static struct rte_timer dp_flow_aging_timer;
static struct rte_timer dp_maintenance_timer;
static struct rte_timer dp_stats_timer;
static uint64_t dp_timer_manage_interval_cycles;

static void dp_flow_aging_timer_cb(__rte_unused struct rte_timer *timer, __rte_unused void *arg)
{
	int ret = dp_send_event_flow_aging_msg();

	if (DP_FAILED(ret))
		DPS_LOG_WARNING("Cannot send flow aging event %s", dp_strerror(ret));
}

static void dp_maintenance_timer_cb(__rte_unused struct rte_timer *timer, __rte_unused void *arg)
{
	if (dp_conf_is_ipv6_overlay_enabled()) {
		trigger_nd_ra();
		trigger_nd_unsol_adv();
	}
	trigger_garp();
}

uint64_t dp_timers_get_manage_interval_cycles()
{
	return dp_timer_manage_interval_cycles;
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

int dp_timers_init()
{
	int ret;
	int flow_aging_interval = TIMER_FLOW_AGING_INTERVAL;

#ifdef ENABLE_PYTEST
	if (flow_aging_interval > dp_conf_get_flow_timeout())
		flow_aging_interval = dp_conf_get_flow_timeout();
#endif

	ret = rte_timer_subsystem_init();
	if (DP_FAILED(ret)) {
		DPS_LOG_ERR("Cannot init timer subsystem %s", dp_strerror(ret));
		return ret;
	}

	if (DP_FAILED(dp_timers_add(&dp_flow_aging_timer, flow_aging_interval, dp_flow_aging_timer_cb))) {
		DPS_LOG_ERR("Cannot start flow aging timer");
		return DP_ERROR;
	}

	if (DP_FAILED(dp_timers_add(&dp_maintenance_timer, TIMER_DP_MAINTENANCE_INTERVAL, dp_maintenance_timer_cb))) {
		DPS_LOG_ERR("Cannot start maintenance timer");
		return DP_ERROR;
	}

	return DP_OK;
}

void dp_timers_free()
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
