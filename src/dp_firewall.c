#include "dp_firewall.h"
#include <stdbool.h>
#include "dp_error.h"
#include "dp_lpm.h"
#include "dp_mbuf_dyn.h"
#include "grpc/dp_grpc_responder.h"

void dp_init_firewall_rules_list(int port_id)
{
	TAILQ_INIT(dp_get_fwall_head(port_id));
}

int dp_add_firewall_rule(struct dp_fwall_rule *new_rule, int port_id)
{
	struct dp_fwall_rule *rule = rte_zmalloc("firewall_rule", sizeof(struct dp_fwall_rule), RTE_CACHE_LINE_SIZE);

	if (!rule)
		return DP_ERROR;

	*rule = *new_rule;
	TAILQ_INSERT_TAIL(dp_get_fwall_head(port_id), rule, next_rule);

	return DP_OK;
}


int dp_delete_firewall_rule(char *rule_id, int port_id)
{
	struct dp_fwall_head *fwall_head = dp_get_fwall_head(port_id);
	struct dp_fwall_rule *rule, *next_rule;

	for (rule = TAILQ_FIRST(fwall_head); rule != NULL; rule = next_rule) {
		next_rule = TAILQ_NEXT(rule, next_rule);
		if (memcmp(rule->rule_id, rule_id, sizeof(rule->rule_id)) == 0) {
			TAILQ_REMOVE(fwall_head, rule, next_rule);
			rte_free(rule);
			return DP_OK;
		}
	}

	return DP_ERROR;
}

struct dp_fwall_rule *dp_get_firewall_rule(char *rule_id, int port_id)
{
	struct dp_fwall_rule *rule;

	TAILQ_FOREACH(rule, dp_get_fwall_head(port_id), next_rule)
		if (memcmp(rule->rule_id, rule_id, sizeof(rule->rule_id)) == 0)
			return rule;

	return NULL;
}

int dp_list_firewall_rules(int port_id, struct dp_grpc_responder *responder)
{
	struct dpgrpc_fwrule_info *reply;
	struct dp_fwall_rule *rule;

	dp_grpc_set_multireply(responder, sizeof(*reply));

	TAILQ_FOREACH(rule, dp_get_fwall_head(port_id), next_rule) {
		reply = dp_grpc_add_reply(responder);
		if (!reply)
			return DP_ERROR;
		reply->rule = *rule;
	}

	return DP_OK;
}

static bool __rte_always_inline dp_is_rule_matching(const struct dp_fwall_rule *rule,
													struct dp_flow *df,
													__rte_unused struct rte_ipv4_hdr *ipv4_hdr)
{
	uint32_t dest_ip = ntohl(df->dst.dst_addr);
	uint32_t src_ip = ntohl(df->src.src_addr);
	uint32_t src_port_lower, src_port_upper = 0;
	uint32_t dst_port_lower, dst_port_upper = 0;
	uint32_t r_dest_ip = ntohl(rule->dest_ip);
	uint32_t r_src_ip = ntohl(rule->src_ip);
	uint8_t protocol = df->l4_type;
	uint8_t r_icmp_type, r_icmp_code;
	uint16_t dest_port = 0;
	uint16_t src_port = 0;

	switch (df->l4_type) {
	case IPPROTO_TCP:
		if ((rule->protocol != IPPROTO_TCP) && (rule->protocol != DP_FWALL_MATCH_ANY_PROTOCOL))
			return false;
	break;
	case IPPROTO_UDP:
		if ((rule->protocol != IPPROTO_UDP) && (rule->protocol != DP_FWALL_MATCH_ANY_PROTOCOL))
			return false;
	break;
	case IPPROTO_ICMP:
		if ((rule->protocol != IPPROTO_ICMP) && (rule->protocol != DP_FWALL_MATCH_ANY_PROTOCOL))
			return false;
		r_icmp_type = ntohl(rule->filter.icmp.icmp_type);
		r_icmp_code = ntohl(rule->filter.icmp.icmp_code);
		if (((rule->filter.icmp.icmp_type == DP_FWALL_MATCH_ANY_ICMP_TYPE) ||
			(df->l4_info.icmp_field.icmp_type == r_icmp_type)) &&
			((rule->filter.icmp.icmp_code == DP_FWALL_MATCH_ANY_ICMP_CODE) ||
			(df->l4_info.icmp_field.icmp_code == r_icmp_code)) &&
			((rule->protocol == DP_FWALL_MATCH_ANY_PROTOCOL) || (rule->protocol == protocol)))
			return true;
	break;
	default:
		return false;
	break;
	}

	src_port = ntohs(df->l4_info.trans_port.src_port);
	dest_port = ntohs(df->l4_info.trans_port.dst_port);
	src_port_lower = rule->filter.tcp_udp.src_port.lower;
	src_port_upper = rule->filter.tcp_udp.src_port.upper;
	dst_port_lower = rule->filter.tcp_udp.dst_port.lower;
	dst_port_upper = rule->filter.tcp_udp.dst_port.upper;

	return ((src_ip & rule->src_ip_mask) == (r_src_ip & rule->src_ip_mask) &&
		(dest_ip & rule->dest_ip_mask) == (r_dest_ip & rule->dest_ip_mask) &&
		((src_port_lower == DP_FWALL_MATCH_ANY_PORT) ||
		 (src_port >= src_port_lower && src_port <= src_port_upper)) &&
		((dst_port_lower == DP_FWALL_MATCH_ANY_PORT) ||
		(dest_port >= dst_port_lower && dest_port <= dst_port_upper)) &&
		((rule->protocol == DP_FWALL_MATCH_ANY_PROTOCOL) || (rule->protocol == protocol)));
}

static struct dp_fwall_rule __rte_always_inline *dp_is_matched_in_fwall_list(struct dp_flow *df,
																	  struct rte_ipv4_hdr *ipv4_hdr,
																	  struct dp_fwall_head *fwall_head,
																	  enum dp_fwall_direction dir,
																	  uint32_t *egress_rule_count)
{
	struct dp_fwall_rule *rule = NULL;

	TAILQ_FOREACH(rule, fwall_head, next_rule) {
		if (rule->dir == DP_FWALL_EGRESS)
			(*egress_rule_count)++;
		if ((dir == rule->dir) && dp_is_rule_matching(rule, df, ipv4_hdr))
			return rule;
	}

	return rule;
}

/* Egress default for the traffic originating from VFs is "Accept", when no rule matches. If there is at least one */
/* Egress rule than the default action becomes drop, if there is no rule matching */
/* Another approach here could be to install a default egress rule for each interface which allows everything */
static enum dp_fwall_action __rte_always_inline dp_get_egress_action(struct dp_flow *df, struct rte_ipv4_hdr *ipv4_hdr,
																	 struct dp_fwall_head *fwall_head)
{
	uint32_t egress_rule_count = 0;
	struct dp_fwall_rule *rule;

	rule = dp_is_matched_in_fwall_list(df, ipv4_hdr, fwall_head, DP_FWALL_EGRESS, &egress_rule_count);

	if (rule)
		return rule->action;
	else if (egress_rule_count == 0)
		return DP_FWALL_ACCEPT;
	else
		return DP_FWALL_DROP;
}

enum dp_fwall_action dp_get_firewall_action(struct dp_flow *df, struct rte_ipv4_hdr *ipv4_hdr, int sender_port_id)
{
	enum dp_fwall_action egress_action = DP_FWALL_DROP, ingress_action = DP_FWALL_DROP;
	struct dp_fwall_head *fwall_head_sender = dp_get_fwall_head(sender_port_id);
	struct dp_fwall_rule *rule;

	if (dp_port_is_pf(df->nxt_hop)) { /* Outgoing traffic to PF (VF Egress, PF Ingress), PF has no Ingress rules */
		return dp_get_egress_action(df, ipv4_hdr, fwall_head_sender);
	} else { /* Incoming traffic */
		if (dp_port_is_pf(sender_port_id))/* Incoming from PF, PF has no Egress rules */
			egress_action = DP_FWALL_ACCEPT;
		else/* Incoming from VF. Check originating VF's Egress rules */
			egress_action = dp_get_egress_action(df, ipv4_hdr, fwall_head_sender);

		rule = dp_is_matched_in_fwall_list(df, ipv4_hdr, dp_get_fwall_head(df->nxt_hop), DP_FWALL_INGRESS, NULL);
		if (rule)
			ingress_action = rule->action;

		if ((ingress_action == DP_FWALL_ACCEPT) && (egress_action == DP_FWALL_ACCEPT))
			return rule->action;
	}

	return DP_FWALL_DROP;
}

void dp_del_all_firewall_rules(int port_id)
{
	struct dp_fwall_head *fwall_head = dp_get_fwall_head(port_id);
	struct dp_fwall_rule *rule;

	if (!fwall_head)
		return;

	while ((rule = TAILQ_FIRST(fwall_head)) != NULL) {
		TAILQ_REMOVE(fwall_head, rule, next_rule);
		rte_free(rule);
	}
}
