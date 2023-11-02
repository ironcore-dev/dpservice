#include "monitoring/dp_monitoring.h"
#include "dp_log.h"
#include "monitoring/dp_event.h"


static struct dp_capture_hdr_config capture_hdr_config = {0};
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
	}

	rte_pktmbuf_free(m);
}

void dp_set_capture_hdr_config(uint8_t *addr, uint32_t udp_src_port, uint32_t udp_dst_port)
{
	rte_memcpy(capture_hdr_config.capture_node_ipv6_addr, addr, sizeof(capture_hdr_config.capture_node_ipv6_addr));
	capture_hdr_config.capture_udp_src_port = udp_src_port;
	capture_hdr_config.capture_udp_dst_port = udp_dst_port;
}

const struct dp_capture_hdr_config *dp_get_capture_hdr_config(void)
{
	return &capture_hdr_config;
}

void dp_set_capture_enabled(bool enabled)
{
	capture_enabled = enabled;
}

bool dp_is_capture_enabled(void)
{
	return capture_enabled;
}
