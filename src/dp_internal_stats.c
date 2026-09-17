// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#include "dp_internal_stats.h"

#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_malloc.h>
#include <rte_seqlock.h>
#include <rte_stdatomic.h>
#include <string.h>

#include "dp_error.h"
#include "dp_firewall.h"
#include "dp_log.h"
#include "dp_lpm.h"
#include "dp_port.h"
#include "dpdk_layer.h"
#include "monitoring/dp_event.h"

struct dp_fwall_telemetry_rule {
	char		rule_id[DP_FIREWALL_ID_MAX_LEN];
	uint64_t	hits;
};

struct dp_fwall_telemetry_iface {
	char							iface_id[DP_IFACE_ID_MAX_LEN];
	uint32_t						rule_count;
	struct dp_fwall_telemetry_rule	rules[DP_FWALL_TELEMETRY_MAX_RULES];
};

// Written by the worker only, read by the telemetry threads
struct dp_fwall_telemetry_snapshot {
	// incremented after every refresh request, even one served by the current snapshot
	RTE_ATOMIC(uint64_t)			handled_requests;
	rte_seqlock_t					lock;
	uint32_t						iface_count;
	struct dp_fwall_telemetry_iface	ifaces[DP_MAX_VF_PORTS];
};

static struct dp_fwall_telemetry_snapshot *fwall_snapshot = NULL;
// only used by the worker
static uint64_t fwall_snapshot_cycles = 0;

int dp_nat_get_used_ports_telemetry(struct rte_tel_data *dict)
{
	const struct dp_ports *ports = dp_get_ports();
	int ret;

	DP_FOREACH_PORT(ports, port) {
		if (port->is_pf || !port->allocated)
			continue;

		ret = rte_tel_data_add_dict_uint(dict, port->iface.id, port->stats.nat_stats.used_port_cnt);
		if (DP_FAILED(ret)) {
			DPS_LOG_ERR("Failed to add interface used nat port telemetry data", DP_LOG_PORT(port), DP_LOG_RET(ret));
			return ret;
		}
	}

	return DP_OK;
}

int dp_fwall_get_rule_count_telemetry(struct rte_tel_data *dict)
{
	const struct dp_ports *ports = dp_get_ports();
	int ret;

	DP_FOREACH_PORT(ports, port) {
		if (port->is_pf || !port->allocated)
			continue;

		ret = rte_tel_data_add_dict_uint(dict, port->iface.id, port->iface.fwall_rule_count);
		if (DP_FAILED(ret)) {
			DPS_LOG_ERR("Failed to add interface firewall rule count telemetry data", DP_LOG_PORT(port), DP_LOG_RET(ret));
			return ret;
		}
	}

	return DP_OK;
}

// Called by the telemetry threads, sleeping here does not delay the worker
// If the worker does not respond in time, the reply comes from the current (older) snapshot
static void dp_fwall_telemetry_wait_for_refresh(uint64_t handled_requests)
{
	uint32_t waited_ms = 0;
	uint32_t delay_ms = 1;

	while (rte_atomic_load_explicit(&fwall_snapshot->handled_requests, rte_memory_order_relaxed) == handled_requests) {
		if (waited_ms >= DP_FWALL_TELEMETRY_REFRESH_TIMEOUT_MS)
			return;
		delay_ms = RTE_MIN(delay_ms, DP_FWALL_TELEMETRY_REFRESH_TIMEOUT_MS - waited_ms);
		rte_delay_us_sleep(delay_ms * 1000);
		waited_ms += delay_ms;
		delay_ms *= 2;
	}
}

int dp_fwall_get_rule_hits_telemetry(const char *iface_id, struct rte_tel_data *dict)
{
	struct dp_fwall_telemetry_rule rules[DP_FWALL_TELEMETRY_MAX_RULES];
	const struct dp_fwall_telemetry_iface *iface;
	uint64_t handled_requests;
	uint32_t iface_count;
	uint32_t rule_count;
	unsigned int seq;
	bool found;
	int ret;

	if (!iface_id)
		return -EINVAL;

	// The counter has to be read before sending the request, otherwise the worker could handle it in between
	// (failure to send is logged by the callee, there is nothing to wait for then)
	handled_requests = rte_atomic_load_explicit(&fwall_snapshot->handled_requests, rte_memory_order_relaxed);
	if (DP_SUCCESS(dp_send_event_firewall_telemetry_msg()))
		dp_fwall_telemetry_wait_for_refresh(handled_requests);

	do {
		seq = rte_seqlock_read_begin(&fwall_snapshot->lock);
		found = false;
		rule_count = 0;
		// values read during a write can be inconsistent, they are only used within bounds and discarded by the retry
		iface_count = RTE_MIN(fwall_snapshot->iface_count, (uint32_t)RTE_DIM(fwall_snapshot->ifaces));
		for (uint32_t i = 0; i < iface_count; ++i) {
			iface = &fwall_snapshot->ifaces[i];
			if (strncmp(iface->iface_id, iface_id, sizeof(iface->iface_id)) == 0) {
				rule_count = RTE_MIN(iface->rule_count, (uint32_t)RTE_DIM(rules));
				memcpy(rules, iface->rules, rule_count * sizeof(rules[0]));
				found = true;
				break;
			}
		}
	} while (rte_seqlock_read_retry(&fwall_snapshot->lock, seq));

	if (!found)
		return -ENODEV;

	for (uint32_t i = 0; i < rule_count; ++i) {
		ret = rte_tel_data_add_dict_uint(dict, rules[i].rule_id, rules[i].hits);
		if (DP_FAILED(ret)) {
			DPS_LOG_ERR("Failed to add firewall rule hit telemetry data", DP_LOG_IFACE(iface_id), DP_LOG_RET(ret));
			return ret;
		}
	}

	return DP_OK;
}

static void dp_fwall_telemetry_write_snapshot(void)
{
	const struct dp_ports *ports = dp_get_ports();
	struct dp_fwall_telemetry_iface *iface;
	struct dp_fwall_rule *rule;
	uint32_t iface_count = 0;
	bool truncated = false;

	rte_seqlock_write_lock(&fwall_snapshot->lock);

	DP_FOREACH_PORT(ports, port) {
		if (port->is_pf || !port->allocated)
			continue;
		if (iface_count >= RTE_DIM(fwall_snapshot->ifaces))
			break;

		iface = &fwall_snapshot->ifaces[iface_count++];
		memcpy(iface->iface_id, port->iface.id, sizeof(iface->iface_id));
		iface->rule_count = 0;
		TAILQ_FOREACH(rule, &port->iface.fwall_head, next_rule) {
			if (iface->rule_count >= RTE_DIM(iface->rules)) {
				truncated = true;
				break;
			}
			memcpy(iface->rules[iface->rule_count].rule_id, rule->rule_id, sizeof(iface->rules[0].rule_id));
			iface->rules[iface->rule_count].hits = rule->stats.rule_hit;
			iface->rule_count++;
		}
	}
	fwall_snapshot->iface_count = iface_count;

	rte_seqlock_write_unlock(&fwall_snapshot->lock);

	if (truncated)
		DPS_LOG_WARNING("Firewall rule hits telemetry does not contain all rules", DP_LOG_MAX(DP_FWALL_TELEMETRY_MAX_RULES));
}

void dp_fwall_telemetry_refresh(void)
{
	uint64_t cur_cycles = rte_get_timer_cycles();
	uint64_t handled_requests;

	// requests within the interval are served by the same snapshot
	if (!fwall_snapshot_cycles || cur_cycles - fwall_snapshot_cycles >= DP_FWALL_TELEMETRY_REFRESH_INTERVAL * rte_get_timer_hz()) {
		fwall_snapshot_cycles = cur_cycles;
		dp_fwall_telemetry_write_snapshot();
	}

	// only the worker writes, so load + store is enough (no fetch_add), the store is atomic for the telemetry readers
	handled_requests = rte_atomic_load_explicit(&fwall_snapshot->handled_requests, rte_memory_order_relaxed);
	rte_atomic_store_explicit(&fwall_snapshot->handled_requests, handled_requests + 1, rte_memory_order_relaxed);
}

int dp_fwall_telemetry_init(void)
{
	fwall_snapshot = rte_zmalloc("fwall_telemetry_snapshot", sizeof(*fwall_snapshot), RTE_CACHE_LINE_SIZE);
	if (!fwall_snapshot) {
		DPS_LOG_ERR("Cannot allocate firewall telemetry snapshot");
		return DP_ERROR;
	}
	rte_seqlock_init(&fwall_snapshot->lock);
	return DP_OK;
}

void dp_fwall_telemetry_free(void)
{
	rte_free(fwall_snapshot);
	fwall_snapshot = NULL;
}
