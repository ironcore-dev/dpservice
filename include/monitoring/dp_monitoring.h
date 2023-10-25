#ifndef __INCLUDE_DP_MONITORING_H__
#define __INCLUDE_DP_MONITORING_H__

#include <stdint.h>
#include <rte_mbuf.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DP_CAPTURE_MAX_PORT_NUM 16

enum dp_event_type {
	DP_EVENT_TYPE_LINK_STATUS,
	DP_EVENT_TYPE_FLOW_AGING,
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

void dp_set_capture_node_ipv6_addr(uint8_t *addr);
void dp_set_capture_udp_src_port(uint32_t port);

void dp_set_capture_udp_dst_port(uint32_t port);
uint8_t *dp_get_capture_node_ipv6_addr(void);
uint16_t dp_get_capture_udp_src_port(void);
uint16_t dp_get_capture_udp_dst_port(void);

void dp_set_capture_enabled(bool enabled);

bool dp_get_capture_enabled(void);

#ifdef __cplusplus
}
#endif
#endif /* __INCLUDE_DP_MONITORING_H__ */
