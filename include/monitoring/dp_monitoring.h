#ifndef __INCLUDE_DP_MONITORING_H__
#define __INCLUDE_DP_MONITORING_H__

#include <stdint.h>
#include <rte_mbuf.h>

#ifdef __cplusplus
extern "C" {
#endif

enum dp_status_type {
	DP_STATUS_TYPE_UNKNOWN,
	DP_STATUS_TYPE_LINK,
	DP_STATUS_TYPE_FLOW_AGING,
};

enum dp_status_scope {
	DP_STATUS_SCOPE_LOCAL,
	DP_STATUS_SCOPE_REMOTE,
};

struct dp_event_msg_head {
	enum dp_status_type type;
	enum dp_status_scope scope;
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
