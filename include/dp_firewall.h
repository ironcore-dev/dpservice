#ifndef __INCLUDE_DP_FIREWALL_H__
#define __INCLUDE_DP_FIREWALL_H__

#ifdef __cplusplus
extern "C" {
#endif
#include <sys/queue.h>
#include <rte_common.h>
#include "node_api.h"
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

/* This needs to be a typedef because of the TAILQ macros used on it */
typedef struct dp_fwall_rule {
	char		rule_id[DP_FIREWALL_ID_STR_LEN];
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
} dp_fwall_rule;

void dp_init_firewall_rules_list(int port_id);
int dp_add_firewall_rule(dp_fwall_rule *new_rule, int port_id);
int dp_delete_firewall_rule(char *rule_id, int port_id);
dp_fwall_rule *dp_get_firewall_rule(char *rule_id, int port_id);
enum dp_fwall_action dp_get_firewall_action(struct dp_flow *df_ptr, struct rte_ipv4_hdr *ipv4_hdr, int sender_port_id);
int dp_list_firewall_rules(int port_id, struct rte_mbuf *m, struct rte_mbuf *rep_arr[]);
void dp_del_all_firewall_rules(int port_id);
int dp_firewall_mask_to_pfx_length(uint32_t mask);

#ifdef __cplusplus
}
#endif

#endif