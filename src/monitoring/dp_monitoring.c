#include "monitoring/dp_monitoring.h"
#include "dp_log.h"
#include "monitoring/dp_event.h"


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
