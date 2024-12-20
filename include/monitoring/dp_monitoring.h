// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#ifndef __INCLUDE_DP_MONITORING_H__
#define __INCLUDE_DP_MONITORING_H__

#include <stdint.h>
#include <rte_ether.h>
#include <rte_mbuf.h>
#include "dp_ipaddr.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DP_CAPTURE_MAX_PORT_NUM 16

enum dp_event_type {
	DP_EVENT_TYPE_LINK_STATUS,
	DP_EVENT_TYPE_FLOW_AGING,
	DP_EVENT_TYPE_NEIGHMAC,
};

struct dp_event_msg_head {
	enum dp_event_type type;
};

struct dp_link_status {
	uint16_t port_id;
	uint8_t status;
};

struct dp_neighmac {
	uint16_t port_id;
	struct rte_ether_addr mac;
};

struct dp_event_msg {
	struct dp_event_msg_head msg_head;
	union {
		struct dp_link_status link_status;
		struct dp_neighmac neighmac;
	} event_entry;
};

struct dp_capture_hdr_config {
	union dp_ipv6 capture_node_ipv6_addr;
	uint16_t capture_udp_src_port;
	uint16_t capture_udp_dst_port;
};

void dp_process_event_msg(struct rte_mbuf *m);


void dp_set_capture_hdr_config(const union dp_ipv6 *addr, uint16_t udp_src_port, uint16_t udp_dst_port);
const struct dp_capture_hdr_config *dp_get_capture_hdr_config(void);

void dp_set_capture_enabled(bool enabled);

bool dp_is_capture_enabled(void);

#ifdef __cplusplus
}
#endif
#endif /* __INCLUDE_DP_MONITORING_H__ */
