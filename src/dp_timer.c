#include <unistd.h>
#include "dp_timer.h"
#include "monitoring/dp_event.h"
#include "dp_log.h"
#include "dp_periodic_msg.h"

static struct rte_timer dp_message_timer;
static struct rte_timer dp_maintenance_timer;
static uint64_t dp_timer_manage_interval;

static uint64_t rte_timer_resolution_in_hz;

static void dp_message_timer_cb()
{
	// printf("message timer is triggerd \n");
	if (DP_FAILED(dp_send_event_timer_msg()))
		DPS_LOG_WARNING("Cannot send timer event");
}

static void dp_maintenance_timer_cb()
{
	// printf("maintainance timer is triggerd \n");
	if (dp_conf_is_ipv6_overlay_enabled()) {
		trigger_nd_ra();
		trigger_nd_unsol_adv();
	}
	trigger_garp();
}

uint64_t dp_get_rte_timer_resolution()
{
	return rte_timer_resolution_in_hz;
}

uint64_t dp_get_timer_manage_interval()
{
	return dp_timer_manage_interval;
}

int timers_init()
{
	int ret;
	unsigned int lcore_id;

	rte_timer_resolution_in_hz = rte_get_timer_hz();
	dp_timer_manage_interval = dp_get_rte_timer_resolution() * TIMER_MANAGE_INTERVAL;
	
	ret = rte_timer_subsystem_init();
	if (DP_FAILED(ret)) {
		DPS_LOG_ERR("Cannot init timer subsystem %s", dp_strerror(ret));
		return ret;
	}

	rte_timer_init(&dp_message_timer);
	rte_timer_init(&dp_maintenance_timer);

	lcore_id = rte_lcore_id();
	ret = rte_timer_reset(&dp_message_timer,
						  dp_get_rte_timer_resolution() * TIMER_MESSAGE_INTERVAL,
						  PERIODICAL,
						  lcore_id,
						  dp_message_timer_cb,
						  NULL);
	// lcore_id = rte_get_next_lcore(lcore_id, 0, 1);
	ret = rte_timer_reset(&dp_maintenance_timer,
						  dp_get_rte_timer_resolution() * TIMER_DP_MAINTAINANCE_INTERVAL,
						  PERIODICAL,
						  lcore_id,
						  dp_maintenance_timer_cb,
						  NULL);
	
	if (DP_FAILED(ret)) {
		DPS_LOG_ERR("Cannot start message timer");  // there is no errno for this
		return DP_ERROR;
	}

	return DP_OK;
}

void timers_free()
{
	rte_timer_subsystem_finalize();
}
