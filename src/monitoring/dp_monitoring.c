#include "monitoring/dp_monitoring.h"


void dp_process_status_msg(struct rte_mbuf *m)
{
	dp_status_msg *status_msg = rte_pktmbuf_mtod(m, dp_status_msg *);

	switch (status_msg->msg_head.type) {
		case DP_STATUS_TYPE_LINK:
			dp_process_link_status_msg(m);
			break;
		default:
			printf("Unknown dp status msg type \n");
	}

	rte_pktmbuf_free(m);

}