#ifndef _DP_INTERNAL_STATS_H_
#define _DP_INTERNAL_STATS_H_

#include <rte_telemetry.h>
#include "dp_port.h"
#include "dp_log.h"

#ifdef __cplusplus
extern "C" {
#endif

struct dp_internal_nat_stats {
	uint16_t dp_stat_nat_used_port_cnt[DP_MAX_VF_PORTS + 2];
};

struct dp_internal_stats {
	struct dp_internal_nat_stats nat_stats;
};

extern struct dp_internal_stats _dp_stats;

#define DP_STATS_NAT_INC_USED_PORT_CNT(port_id) \
do { \
	_dp_stats.nat_stats.dp_stat_nat_used_port_cnt[port_id]++;	\
} \
while (0)

#define DP_STATS_NAT_DEC_USED_PORT_CNT(port_id) \
do { \
	_dp_stats.nat_stats.dp_stat_nat_used_port_cnt[port_id]++;	\
} \
while (0)

int dp_nat_get_used_ports_telemetry(struct rte_tel_data *dict);

#ifdef __cplusplus
}
#endif
#endif
