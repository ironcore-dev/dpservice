#include "monitoring/dp_monitoring.h"
#include "dp_log.h"
#include "monitoring/dp_event.h"

static uint8_t capture_node_ipv6_addr[16] = {0};
static uint32_t capture_udp_src_port = 0;
static uint32_t capture_udp_dst_port = 0;
static bool capture_enabled = false;


void dp_process_event_msg(struct rte_mbuf *m)
{
	struct dp_event_msg *event_msg = rte_pktmbuf_mtod(m, struct dp_event_msg *);

	switch (event_msg->msg_head.type) {
	case DP_EVENT_TYPE_LINK_STATUS:
		dp_process_event_link_msg(m);
		break;
	case DP_EVENT_TYPE_FLOW_AGING:
		dp_process_event_flow_aging_msg(m);
		break;
	case DP_EVENT_TYPE_HARDWARE_CAPTURE_START:
		dp_process_event_hardware_capture_start_msg(m);
		break;
	case DP_EVENT_TYPE_HARDWARE_CAPTURE_STOP:
		dp_process_event_hardware_capture_stop_msg(m);
		break;
	default:
		DPS_LOG_WARNING("Unknown monitoring status message type", DP_LOG_VALUE(event_msg->msg_head.type));
	}

	rte_pktmbuf_free(m);
}

void dp_set_capture_node_ipv6_addr(uint8_t *addr)
{
	rte_memcpy(capture_node_ipv6_addr, addr, sizeof(capture_node_ipv6_addr));
}

void dp_set_capture_udp_src_port(uint32_t port)
{
	capture_udp_src_port = port;
}

void dp_set_capture_udp_dst_port(uint32_t port)
{
	capture_udp_dst_port = port;
}

uint8_t *dp_get_capture_node_ipv6_addr(void)
{
	return capture_node_ipv6_addr;
}

uint16_t dp_get_capture_udp_src_port(void)
{
	return (uint16_t)capture_udp_src_port;
}

uint16_t dp_get_capture_udp_dst_port(void)
{
	return (uint16_t)capture_udp_dst_port;
}

void dp_set_capture_enabled(bool enabled)
{
	capture_enabled = enabled;
}

bool dp_get_capture_enabled(void)
{
	return capture_enabled;
}
