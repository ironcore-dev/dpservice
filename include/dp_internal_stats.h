#ifndef _DP_INTERNAL_STATS_H_
#define _DP_INTERNAL_STATS_H_

#include <rte_telemetry.h>
#include "dp_log.h"

#ifdef __cplusplus
extern "C" {
#endif

struct dp_nat_stats {
	uint16_t used_port_cnt;
};

struct dp_port_stats {
	struct dp_nat_stats nat_stats;
};

#define DP_STATS_NAT_INC_USED_PORT_CNT(PORT) do { \
	(PORT)->stats.nat_stats.used_port_cnt++; \
} while (0)

#define DP_STATS_NAT_DEC_USED_PORT_CNT(PORT) do { \
	(PORT)->stats.nat_stats.used_port_cnt--; \
} while (0)

int dp_nat_get_used_ports_telemetry(struct rte_tel_data *dict);

#ifdef __cplusplus
}
#endif
#endif
