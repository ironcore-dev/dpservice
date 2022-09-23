#include <rte_common.h>
#include "dp_util.h"
#include "dp_flow.h"
#include "monitoring/dp_event.h"

void dp_port_set_link_status(struct dp_dpdk_layer *dp_layer, int port_id, uint8_t status)
{
	for (int i = 0; i < DP_MAX_PORTS; i++) {
		if (dp_layer->ports[i]->dp_port_id == port_id) {
			dp_layer->ports[i]->link_status = status;
			break;
		}
	}
}

uint8_t dp_port_get_link_status(struct dp_dpdk_layer *dp_layer, int port_id)
{
	uint8_t ret = RTE_ETH_LINK_DOWN;

	for (int i = 0; i < DP_MAX_PORTS; i++) {
		if (dp_layer->ports[i]->dp_port_id == port_id) {
			ret = dp_layer->ports[i]->link_status;
			break;
		}
	}
	return ret;
}

static int dp_send_event_link_msg(uint16_t port_id, uint8_t status)
{
	dp_event_msg link_status_msg = {0};
	int ret;

	link_status_msg.msg_head.type = DP_STATUS_TYPE_LINK;
	link_status_msg.msg_head.scope = DP_STATUS_SCOPE_LOCAL;
	link_status_msg.event_entry.link_status.port_id = port_id;
	link_status_msg.event_entry.link_status.status = status;

	struct rte_mbuf *m = rte_pktmbuf_alloc(get_dpdk_layer()->rte_mempool);
	dp_event_msg *status_msg = rte_pktmbuf_mtod(m, dp_event_msg*);

	memcpy(status_msg, &link_status_msg, sizeof(link_status_msg));

	ret = rte_ring_sp_enqueue(get_dpdk_layer()->monitoring_rx_queue, m);
	if (ret < 0)
		return ret;

	return 0;
}

int dp_link_status_change_event_callback(uint16_t port_id, enum rte_eth_event_type type, void *param,
									 void *ret_param)
{
	struct rte_eth_link link;
	int ret;

	RTE_SET_USED(param);
	RTE_SET_USED(ret_param);

	ret = rte_eth_link_get_nowait(port_id, &link);
	if (ret < 0) {
		printf("Failed link get on port %d: %s\n",
			   port_id, rte_strerror(-ret));
		return ret;
	}

	ret = dp_send_event_link_msg(port_id, link.link_status);
	if (ret < 0)
		return ret;

	return 0;
}

void dp_process_event_link_msg(struct rte_mbuf *m)
{
	dp_event_msg *status_msg = rte_pktmbuf_mtod(m, dp_event_msg *);
	uint16_t port_id = status_msg->event_entry.link_status.port_id;
	uint8_t	status = status_msg->event_entry.link_status.status;

	dp_port_set_link_status(get_dpdk_layer(), port_id, status);
}

int dp_send_event_timer_msg()
{
	dp_event_msg timer_msg = {0};
	int ret;

	timer_msg.msg_head.type = DP_STATUS_TYPE_TIMER;
	timer_msg.msg_head.scope = DP_STATUS_SCOPE_LOCAL;

	struct rte_mbuf *m = rte_pktmbuf_alloc(get_dpdk_layer()->rte_mempool);
	dp_event_msg *event_msg = rte_pktmbuf_mtod(m, dp_event_msg*);

	memcpy(event_msg, &timer_msg, sizeof(dp_event_msg));

	ret = rte_ring_sp_enqueue(get_dpdk_layer()->monitoring_rx_queue, m);
	if (ret < 0)
		return ret;

	return 0;
}

void dp_process_event_timer_msg(struct rte_mbuf *m)
{
	if (dp_is_offload_enabled()) {
		dp_process_aged_flows(dp_get_pf0_port_id());
		dp_process_aged_flows(dp_get_pf1_port_id());
	} else {
		dp_process_aged_flows_non_offload();
	}
}