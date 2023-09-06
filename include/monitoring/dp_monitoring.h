#ifndef __INCLUDE_DP_MONITORING_H__
#define __INCLUDE_DP_MONITORING_H__

#include <stdint.h>
#include <rte_mbuf.h>

#ifdef __cplusplus
extern "C" {
#endif

enum dp_event_type {
	DP_EVENT_TYPE_UNKNOWN,
	DP_EVENT_TYPE_LINK_STATUS,
	DP_EVENT_TYPE_FLOW_AGING,
	DP_EVENT_TYPE_HARDWARE_CAPTURE_START,
	DP_EVENT_TYPE_HARDWARE_CAPTURE_STOP,
};

struct dp_event_msg_head {
	enum dp_event_type type;
};

struct dp_link_status {
	uint16_t port_id;
	uint8_t status;
};

struct dp_event_msg {
	struct dp_event_msg_head msg_head;
	union {
		struct dp_link_status link_status;
	} event_entry;
};

void dp_process_event_msg(struct rte_mbuf *m);

#ifdef __cplusplus
}
#endif
#endif /* __INCLUDE_DP_MONITORING_H__ */
