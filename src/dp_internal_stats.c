#include "dp_internal_stats.h"

#include <rte_common.h>
#include <rte_malloc.h>

#include "dp_error.h"
#include "dp_log.h"
#include "dp_lpm.h"

struct dp_internal_stats _dp_stats = {0};

int dp_nat_get_used_ports_telemetry(struct rte_tel_data *dict)
{
	int ret;
	struct dp_ports *ports = get_dp_ports();

	DP_FOREACH_PORT(ports, port) {
		if (port->port_type != DP_PORT_VF || !port->allocated)
			continue;

		ret = rte_tel_data_add_dict_u64(dict, (const char *)dp_get_vm_machineid(port->port_id), _dp_stats.nat_stats.dp_stat_nat_used_port_cnt[port->port_id]);
		if (DP_FAILED(ret)) {
			DPS_LOG_ERR("Failed to add interface used nat port telemetry data", DP_LOG_PORTID(port->port_id), DP_LOG_RET(ret));
			return ret;
		}
	}

	return DP_OK;
}
