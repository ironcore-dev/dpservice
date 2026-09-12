// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

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

// The telemetry threads cannot walk the firewall rules owned by the worker,
// instead the worker copies the rule hits into a snapshot on request, at most once per interval (in seconds)
#ifdef ENABLE_PYTEST
#	define DP_FWALL_TELEMETRY_REFRESH_INTERVAL 0
#else
#	define DP_FWALL_TELEMETRY_REFRESH_INTERVAL 5
#endif
// rules of an interface beyond this limit are not part of the snapshot
#define DP_FWALL_TELEMETRY_MAX_RULES 64

int dp_fwall_get_rule_count_telemetry(struct rte_tel_data *dict);
int dp_fwall_get_rule_hits_telemetry(const char *iface_id, struct rte_tel_data *dict);

int dp_fwall_telemetry_init(void);
void dp_fwall_telemetry_free(void);
void dp_fwall_telemetry_refresh(void);

#ifdef __cplusplus
}
#endif
#endif
