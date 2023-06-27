#include "monitoring/dp_event.h"
#include "dp_conf.h"
#include "dp_error.h"
#include "dp_flow.h"
#include "dp_log.h"
#include "dp_port.h"
#include "monitoring/dp_monitoring.h"


static int dp_send_event_msg(struct dp_event_msg *msg)
{
	struct rte_mbuf *m;
	struct dp_event_msg *mbuf_msg;
	int ret;

	m = rte_pktmbuf_alloc(get_dpdk_layer()->rte_mempool);
	if (!m) {
		DPS_LOG_ERR("Cannot allocate monitoring event message", DP_LOG_VALUE(msg->msg_head.type));
		return DP_ERROR;
	}

	mbuf_msg = rte_pktmbuf_mtod(m, struct dp_event_msg *);
	memcpy(mbuf_msg, msg, sizeof(struct dp_event_msg));

	ret = rte_ring_sp_enqueue(get_dpdk_layer()->monitoring_rx_queue, m);
	if (DP_FAILED(ret)) {
		DPS_LOG_ERR("Cannot enqueue monitoring event message", DP_LOG_VALUE(msg->msg_head.type), DP_LOG_RET(ret));
		return ret;
	}

	return DP_OK;
}

// Link-status message - sent when interface state changes

static int dp_send_event_link_msg(uint16_t port_id, uint8_t status)
{
	struct dp_event_msg link_status_msg = {
		.msg_head = {
			.type = DP_STATUS_TYPE_LINK,
			.scope = DP_STATUS_SCOPE_LOCAL,
		},
		.event_entry = {
			.link_status = {
				.port_id = port_id,
				.status = status,
			},
		},
	};
	return dp_send_event_msg(&link_status_msg);
}

int dp_link_status_change_event_callback(uint16_t port_id,
										 enum rte_eth_event_type type,
										 __rte_unused void *param,
										 __rte_unused void *ret_param)
{
	struct rte_eth_link link;
	int ret;

	ret = rte_eth_link_get_nowait(port_id, &link);
	if (DP_FAILED(ret)) {
		DPS_LOG_ERR("Link change failed to get link", DP_LOG_PORTID(port_id), DP_LOG_RET(ret));
		return ret;
	}

	if (DP_FAILED(dp_send_event_link_msg(port_id, link.link_status)))
		return DP_ERROR;

	return DP_OK;
}

void dp_process_event_link_msg(struct rte_mbuf *m)
{
	struct dp_event_msg *status_msg = rte_pktmbuf_mtod(m, struct dp_event_msg *);
	uint16_t port_id = status_msg->event_entry.link_status.port_id;
	uint8_t status = status_msg->event_entry.link_status.status;

	if (DP_FAILED(dp_port_set_link_status(port_id, status)))
		DPS_LOG_WARNING("Cannot set link status", DP_LOG_PORTID(port_id), DP_LOG_VALUE(status));
}

// Flow-aging message - sent periodically to age-out conntracked flows

int dp_send_event_flow_aging_msg()
{
	struct dp_event_msg flow_aging_msg = {
		.msg_head = {
			.type = DP_STATUS_TYPE_FLOW_AGING,
			.scope = DP_STATUS_SCOPE_LOCAL,
		},
	};
	return dp_send_event_msg(&flow_aging_msg);
}

void dp_process_event_flow_aging_msg(struct rte_mbuf *m)
{
	if (dp_conf_is_offload_enabled()) {
		struct dp_ports *ports = get_dp_ports();

		dp_process_aged_flows(dp_port_get_pf0_id());
		dp_process_aged_flows(dp_port_get_pf1_id());

		DP_FOREACH_PORT(ports, port) {
			if (port->port_type == DP_PORT_VF && port->allocated)
				dp_process_aged_flows(port->port_id);

		}
	}

	// software aged flow and hardware aged flow are binded to a same cntrack obj via shared refcount
	// this cntrack obj gets deleted when the last reference is removed
	// dp_process_aged_flows_non_offload() also takes care of expired tcp hw rte flow rules via the query mechanism,
	// which enables fully control of hw rules' lifecycle from the software path for tcp flows.
	dp_process_aged_flows_non_offload();
}
