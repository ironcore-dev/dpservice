#include "dp_internal_stats.h"

#include <rte_common.h>
#include <rte_malloc.h>

#include "dp_error.h"
#include "dp_log.h"
#include "dp_lpm.h"


struct dp_internal_stats *_dp_stats;

int dp_internal_stats_init()
{
	_dp_stats = rte_zmalloc("dp_internal_stats", sizeof(struct dp_internal_stats), RTE_CACHE_LINE_SIZE);
	if (!_dp_stats) {
		DPS_LOG_ERR("Failed to initialise dp_internal_stats");
		return DP_ERROR;
	}

	return DP_OK;
}

void dp_internal_stats_free()
{
	if (!_dp_stats) {
		DPS_LOG_WARNING("dp_internal_stats does not exist");
		return;
	}

	rte_free(_dp_stats);
	_dp_stats = NULL;
}

int dp_nat_get_used_ports_telemetry(struct rte_tel_data *dict)
{
	int ret;
	struct dp_ports *ports = get_dp_ports();

	DP_FOREACH_PORT(ports, port) {
		if (port->port_type == DP_PORT_VF && port->allocated) {
			ret = rte_tel_data_add_dict_u64(dict, (char *)dp_get_vm_machineid(port->port_id), _dp_stats->nat_stats.dp_stat_nat_used_port_cnt[port->port_id]);
			if (DP_FAILED(ret)) {
				DPS_LOG_ERR("Failed to add interface used nat port telemetry data %s", dp_strerror(ret));
				return ret;
			}
		}
	}

	return DP_OK;
}
