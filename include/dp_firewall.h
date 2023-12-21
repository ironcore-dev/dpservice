// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#ifndef __INCLUDE_DP_FIREWALL_H__
#define __INCLUDE_DP_FIREWALL_H__

#ifdef __cplusplus
extern "C" {
#endif
#include <sys/queue.h>
#include <rte_common.h>
#include "dp_mbuf_dyn.h"
#include "dp_util.h"

#define DP_FWALL_MATCH_ANY_PORT			0xFFFFFFFF
#define DP_FWALL_MATCH_ANY_ICMP_TYPE	0xFFFFFFFF
#define DP_FWALL_MATCH_ANY_ICMP_CODE	0xFFFFFFFF
#define DP_FWALL_MATCH_ANY_PROTOCOL	0
#define DP_FWALL_MATCH_ANY_LENGTH	0

enum dp_fwall_action {
	DP_FWALL_DROP,
	DP_FWALL_ACCEPT
};

enum dp_fwall_direction {
	DP_FWALL_INGRESS,
	DP_FWALL_EGRESS
};

TAILQ_HEAD(dp_fwall_head, dp_fwall_rule);

struct dp_icmp_filter {
	uint32_t icmp_type;
	uint32_t icmp_code;
};

struct dp_port_range {
	uint32_t lower;
	uint32_t upper;
};

struct dp_port_filter {
	struct dp_port_range src_port;
	struct dp_port_range dst_port;
};

struct dp_ip_mask {
	union {
		uint32_t ip4;
		uint8_t ip6[DP_IPV6_ADDR_SIZE];
	};
};

struct dp_fwall_rule {
	char					rule_id[DP_FIREWALL_ID_MAX_LEN];
	struct dp_ip_address	src_ip;
	struct dp_ip_address	dest_ip;
	struct dp_ip_mask		src_mask;
	struct dp_ip_mask		dest_mask;
	uint16_t				priority;
	uint8_t					protocol;
	union {
		struct dp_icmp_filter icmp;
		struct dp_port_filter tcp_udp;
	} filter;
	enum dp_fwall_action action;
	enum dp_fwall_direction dir;
	TAILQ_ENTRY(dp_fwall_rule) next_rule;
};

// forward-declaration due to 'struct dp_fwall_rule' being part of these structures
struct dp_grpc_responder;
struct dp_port;

void dp_init_firewall_rules(struct dp_port *port);
int dp_add_firewall_rule(const struct dp_fwall_rule *new_rule, struct dp_port *port);
int dp_delete_firewall_rule(const char *rule_id, struct dp_port *port);
struct dp_fwall_rule *dp_get_firewall_rule(const char *rule_id, const struct dp_port *port);
enum dp_fwall_action dp_get_firewall_action(struct dp_flow *df, const struct dp_port *in_port, const struct dp_port *out_port);
int dp_list_firewall_rules(const struct dp_port *port, struct dp_grpc_responder *responder);
void dp_del_all_firewall_rules(struct dp_port *port);

#ifdef __cplusplus
}
#endif

#endif
