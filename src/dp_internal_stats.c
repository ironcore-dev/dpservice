// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#include "dp_internal_stats.h"

#include <rte_common.h>
#include <rte_malloc.h>

#include "dp_error.h"
#include "dp_log.h"
#include "dp_lpm.h"
#include "dp_port.h"

int dp_nat_get_used_ports_telemetry(struct rte_tel_data *dict)
{
	const struct dp_ports *ports = dp_get_ports();
	int ret;

	DP_FOREACH_PORT(ports, port) {
		if (port->is_pf || !port->allocated)
			continue;

		ret = rte_tel_data_add_dict_u64(dict, port->iface.id, port->stats.nat_stats.used_port_cnt);
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

		ret = rte_tel_data_add_dict_u64(dict, port->iface.id, port->iface.fwall_rule_count);
		if (DP_FAILED(ret)) {
			DPS_LOG_ERR("Failed to add interface firewall rule count telemetry data", DP_LOG_PORT(port), DP_LOG_RET(ret));
			return ret;
		}
	}

	return DP_OK;
}
