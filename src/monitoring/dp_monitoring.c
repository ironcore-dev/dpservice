#include "monitoring/dp_monitoring.h"
#include "dp_log.h"
#include "monitoring/dp_event.h"


void dp_process_event_msg(struct rte_mbuf *m)
{
	dp_event_msg *event_msg = rte_pktmbuf_mtod(m, dp_event_msg *);

	switch (event_msg->msg_head.type) {
	case DP_STATUS_TYPE_LINK:
		dp_process_event_link_msg(m);
		break;
	case DP_STATUS_TYPE_FLOW_AGING:
		dp_process_event_flow_aging_msg(m);
		break;
	default:
		DPS_LOG_WARNING("Unknown monitoring status message type %d", event_msg->msg_head.type);
	}

	rte_pktmbuf_free(m);
}
