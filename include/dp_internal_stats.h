#ifndef _DP_INTERNAL_STATS_H_
#define _DP_INTERNAL_STATS_H_

#include <rte_telemetry.h>
#include "dp_port.h"
#include "dp_log.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DP_CHECK_INTERNAL_STATS_VALIDITY \
	{ if (!_dp_stats) {DPS_LOG_WARNING("dp_internal_stats is not valid"); return; } }

struct dp_internal_nat_stats {
	uint16_t dp_stat_nat_used_port_cnt[DP_MAX_VF_PORTS + 2];
};

struct dp_internal_stats {
	struct dp_internal_nat_stats nat_stats;
};

extern struct dp_internal_stats *_dp_stats;

int dp_internal_stats_init();
void dp_internal_stats_free();

static __rte_always_inline void dp_stats_nat_inc_used_port_cnt(uint16_t port_id)
{
	DP_CHECK_INTERNAL_STATS_VALIDITY;
	_dp_stats->nat_stats.dp_stat_nat_used_port_cnt[port_id]++;
}

static __rte_always_inline void dp_stats_nat_dec_used_port_cnt(uint16_t port_id)
{
	DP_CHECK_INTERNAL_STATS_VALIDITY;
	_dp_stats->nat_stats.dp_stat_nat_used_port_cnt[port_id]--;
}

int dp_nat_get_used_ports_telemetry(struct rte_tel_data *dict);

#ifdef __cplusplus
}
#endif
#endif
