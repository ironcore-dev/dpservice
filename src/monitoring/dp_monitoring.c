#include "monitoring/dp_monitoring.h"


void dp_process_event_msg(struct rte_mbuf *m)
{
	dp_event_msg *event_msg = rte_pktmbuf_mtod(m, dp_event_msg *);

	switch (event_msg->msg_head.type) {
	case DP_STATUS_TYPE_LINK:
		dp_process_event_link_msg(m);
		break;
	case DP_STATUS_TYPE_TIMER:
		dp_process_event_timer_msg(m);
		break;
	default:
			printf("Unknown dp status msg type \n");
	}

	rte_pktmbuf_free(m);
}