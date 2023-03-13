#include <unistd.h>
#include <rte_timer.h>
#include <rte_cycles.h>
#include "dp_error.h"
#include "dp_log.h"
#include "dp_periodic_msg.h"
#include "dp_timers.h"
#include "dpdk_layer.h"
#include "monitoring/dp_event.h"

// All timer intervale are in seconds:

// how often flow table is checked for timed-out flows
// (as a sampling rate it should be smaller than the actual timeout value)
#define TIMER_FLOW_AGING_INTERVAL 5

// how often to perform network maintenance tasks (ND, GARP, ...)
#define TIMER_DP_MAINTENANCE_INTERVAL 30

// timer for stats printing
#define TIMER_STATS_INTERVAL 1

// NOTE: this needs to be the smallest value of all timer intervals to work properly
// The "sampling rate" for timers
#define TIMER_MANAGE_INTERVAL 1


static struct rte_timer dp_flow_aging_timer;
static struct rte_timer dp_maintenance_timer;
static struct rte_timer dp_stats_timer;
// TODO move inside?
static uint64_t dp_timer_manage_interval;

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

uint64_t dp_timers_get_manage_interval()
{
	return dp_timer_manage_interval;
}

int dp_timers_init()
{
	int ret;
	unsigned int lcore_id;
	uint64_t timer_hz;
	int flow_aging_interval = TIMER_FLOW_AGING_INTERVAL;

#ifdef ENABLE_PYTEST
	if (flow_aging_interval > dp_conf_get_flow_timeout())
		flow_aging_interval = dp_conf_get_flow_timeout();
#endif

	timer_hz = rte_get_timer_hz();
	dp_timer_manage_interval = timer_hz * TIMER_MANAGE_INTERVAL;

	ret = rte_timer_subsystem_init();
	if (DP_FAILED(ret)) {
		DPS_LOG_ERR("Cannot init timer subsystem %s", dp_strerror(ret));
		return ret;
	}

	rte_timer_init(&dp_flow_aging_timer);
	rte_timer_init(&dp_maintenance_timer);

	lcore_id = rte_lcore_id();
	ret = rte_timer_reset(&dp_flow_aging_timer,
						  timer_hz * flow_aging_interval,
						  PERIODICAL,
						  lcore_id,
						  dp_flow_aging_timer_cb,
						  NULL);
	if (DP_FAILED(ret)) {
		DPS_LOG_ERR("Cannot start message timer");  // there is no errno for this
		return DP_ERROR;
	}

	ret = rte_timer_reset(&dp_maintenance_timer,
						  timer_hz * TIMER_DP_MAINTENANCE_INTERVAL,
						  PERIODICAL,
						  lcore_id,
						  dp_maintenance_timer_cb,
						  NULL);

	if (DP_FAILED(ret)) {
		DPS_LOG_ERR("Cannot start maintenance timer");  // there is no errno for this
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
	int ret;

	ret = rte_timer_reset(&dp_stats_timer,
						  rte_get_timer_hz() * TIMER_STATS_INTERVAL,
						  PERIODICAL,
						  rte_lcore_id(),
						  stats_cb,
						  NULL);
	if (DP_FAILED(ret)) {
		DPS_LOG_ERR("Cannot start stats timer");  // there is no errno for this
		return DP_ERROR;
	}

	return DP_OK;
}
