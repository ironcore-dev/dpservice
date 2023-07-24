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

enum dp_fwall_action { DP_FWALL_DROP, DP_FWALL_ACCEPT };
enum dp_fwall_direction { DP_FWALL_INGRESS, DP_FWALL_EGRESS };

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

struct dp_fwall_rule {
	char		rule_id[DP_FIREWALL_ID_MAX_LEN];
	uint32_t	src_ip;
	uint32_t	src_ip_mask;
	uint32_t	dest_ip;
	uint32_t	dest_ip_mask;
	uint16_t	priority;
	uint8_t		protocol;
	union {
		struct dp_icmp_filter icmp;
		struct dp_port_filter tcp_udp;
	} filter;
	enum dp_fwall_action action;
	enum dp_fwall_direction dir;
	TAILQ_ENTRY(dp_fwall_rule) next_rule;
};

// forward-declaration due to 'struct dp_fwall_rule' being part of 'struct dp_grpc_responder'
struct dp_grpc_responder;

void dp_init_firewall_rules_list(int port_id);
int dp_add_firewall_rule(struct dp_fwall_rule *new_rule, int port_id);
int dp_delete_firewall_rule(char *rule_id, int port_id);
struct dp_fwall_rule *dp_get_firewall_rule(char *rule_id, int port_id);
enum dp_fwall_action dp_get_firewall_action(struct dp_flow *df, struct rte_ipv4_hdr *ipv4_hdr, int sender_port_id);
int dp_list_firewall_rules(int port_id, struct dp_grpc_responder *responder);
void dp_del_all_firewall_rules(int port_id);

#ifdef __cplusplus
}
#endif

#endif
