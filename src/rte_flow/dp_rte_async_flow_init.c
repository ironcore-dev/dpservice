#include "rte_flow/dp_rte_async_flow_init.h"
#include "rte_flow/dp_rte_async_flow_isolation.h"

int dp_create_pf_async_templates(struct dp_port *port) {

	DPS_LOG_INFO("Installing PF async templates", DP_LOG_PORTID(port->port_id));

	if (DP_FAILED(dp_create_pf_async_isolation_templates(port))) {
		DPS_LOG_ERR("Failed to create pf async isolation templates", DP_LOG_PORTID(port->port_id));
		return DP_ERROR;
	}

	// add more template pattern/action combinations in the future

	return DP_OK;
}
