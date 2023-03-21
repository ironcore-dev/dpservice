#include <stdbool.h>
#include "node_api.h"
#include "dp_firewall.h"
#include "dp_lpm.h"

#ifdef ENABLE_PYTEST
dp_fwall_rule enable_all_egress = {
	.src_ip = 0,
	.src_ip_mask = 0,
	.filter.tcp_udp.src_port.lower = DP_FWALL_MATCH_ANY_PORT,
	.filter.tcp_udp.src_port.upper = 0,
	.filter.tcp_udp.dst_port.lower = DP_FWALL_MATCH_ANY_PORT,
	.filter.tcp_udp.dst_port.upper = 0,
	.dest_ip = 0,
	.dest_ip_mask = 0,
	.dir = DP_FWALL_EGRESS,
	.protocol = DP_FWALL_MATCH_ANY_PROTOCOL,
	.action = DP_FWALL_ACCEPT
};
dp_fwall_rule enable_all_ingress = {
	.src_ip = 0,
	.src_ip_mask = 0,
	.filter.tcp_udp.src_port.lower = DP_FWALL_MATCH_ANY_PORT,
	.filter.tcp_udp.src_port.upper = 0,
	.filter.tcp_udp.dst_port.lower = DP_FWALL_MATCH_ANY_PORT,
	.filter.tcp_udp.dst_port.upper = 0,
	.dest_ip = 0,
	.dest_ip_mask = 0,
	.dir = DP_FWALL_INGRESS,
	.protocol = DP_FWALL_MATCH_ANY_PROTOCOL,
	.action = DP_FWALL_ACCEPT
};
#endif

static int32_t rule_id_counter = 1;

void dp_init_firewall_rules_list(int port_id)
{
	TAILQ_INIT(dp_get_fwall_head(port_id));
	#ifdef ENABLE_PYTEST
	dp_add_firewall_rule(&enable_all_egress, port_id);
	dp_add_firewall_rule(&enable_all_ingress, port_id);
	#endif
}

static int32_t __rte_always_inline dp_generate_rule_id() {
	return ++rule_id_counter;
}

int32_t dp_add_firewall_rule(dp_fwall_rule *new_rule, int port_id)
{
	int32_t rule_id;

	dp_fwall_rule *rule = rte_zmalloc("firewall_rule", sizeof(struct dp_fwall_rule), RTE_CACHE_LINE_SIZE);
	if (rule == NULL) {
		return -1;
	}
	rule_id = dp_generate_rule_id();
	*rule = *new_rule;
	rule->rule_id = rule_id;
	TAILQ_INSERT_TAIL(dp_get_fwall_head(port_id), rule, next_rule);

	return rule_id;
}


int dp_delete_firewall_rule(int32_t rule_id, int port_id)
{
	dp_fwall_rule *rule, *next_rule;

	for (rule = TAILQ_FIRST(dp_get_fwall_head(port_id)); rule != NULL; rule = next_rule) {
		next_rule = TAILQ_NEXT(rule, next_rule);
		if (rule->rule_id == rule_id) {
			TAILQ_REMOVE(dp_get_fwall_head(port_id), rule, next_rule);
			rte_free(rule);
			return 0;
		}
	}

	return -1;
}

dp_fwall_rule *get_firewall_rule(int32_t rule_id, int port_id)
{
	dp_fwall_rule *rule;

	TAILQ_FOREACH(rule, dp_get_fwall_head(port_id), next_rule) {
		if (rule->rule_id == rule_id) {
			return rule;
		}
	}

	return NULL;
}

void dp_list_firewall_rules(int port_id)
{
	dp_fwall_rule *rule;
	const char *action_str[] = {"DROP", "ACCEPT"};

	TAILQ_FOREACH(rule, dp_get_fwall_head(port_id), next_rule) {
		printf("Rule ID: %d\n", rule->rule_id);
		printf("Src IP: %u\n", rule->src_ip);
		printf("Src IP Mask: %u\n", rule->src_ip_mask);
		printf("Dest IP: %u\n", rule->dest_ip);
		printf("Dest IP Mask: %u\n", rule->dest_ip_mask);
		printf("Protocol: %u\n", rule->protocol);
		printf("Action: %s\n\n", action_str[rule->action]);
	}
}

static bool __rte_always_inline dp_is_rule_matching(const dp_fwall_rule *rule, struct dp_flow *df_ptr, struct rte_ipv4_hdr *ipv4_hdr)
{
	uint32_t dest_ip = ntohl(df_ptr->dst.dst_addr);
	uint32_t src_ip = ntohl(df_ptr->src.src_addr);
	int32_t src_port_lower, src_port_upper = 0;
	int32_t dst_port_lower, dst_port_upper = 0;
	uint8_t protocol = df_ptr->l4_type;
	uint16_t dest_port = 0;
	uint16_t src_port = 0;

	switch (df_ptr->l4_type)
	{
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
			if (rule->filter.icmp.icmp_type != DP_FWALL_MATCH_ANY_ICMP_TYPE && rule->filter.icmp.icmp_type != df_ptr->l4_info.icmp_field.icmp_type)
				return false;
			if (rule->filter.icmp.icmp_code != DP_FWALL_MATCH_ANY_ICMP_CODE && rule->filter.icmp.icmp_code != df_ptr->l4_info.icmp_field.icmp_code)
				return false;
			if (((rule->filter.icmp.icmp_type == DP_FWALL_MATCH_ANY_ICMP_TYPE) ||
				(df_ptr->l4_info.icmp_field.icmp_type == rule->filter.icmp.icmp_type)) &&
				((rule->filter.icmp.icmp_code == DP_FWALL_MATCH_ANY_ICMP_CODE) ||
				(df_ptr->l4_info.icmp_field.icmp_code == rule->filter.icmp.icmp_code)) &&
				((rule->protocol == DP_FWALL_MATCH_ANY_PROTOCOL) || (rule->protocol == protocol)))
				return true;
		break;
		default:
			return false;
		break;
	}

	src_port = ntohs(df_ptr->l4_info.trans_port.src_port);
	dest_port = ntohs(df_ptr->l4_info.trans_port.dst_port);
	src_port_lower = rule->filter.tcp_udp.src_port.lower;
	src_port_upper = rule->filter.tcp_udp.src_port.upper;
	dst_port_lower = rule->filter.tcp_udp.dst_port.lower;
	dst_port_upper = rule->filter.tcp_udp.dst_port.upper;

	if ((src_ip & rule->src_ip_mask) == (rule->src_ip & rule->src_ip_mask) &&
		(dest_ip & rule->dest_ip_mask) == (rule->dest_ip & rule->dest_ip_mask) &&
		((src_port_lower == DP_FWALL_MATCH_ANY_PORT) || 
		 (src_port >= src_port_lower && src_port <= src_port_upper)) &&
		((dst_port_lower == DP_FWALL_MATCH_ANY_PORT) ||
		(dest_port >= dst_port_lower && dest_port <= dst_port_upper)) &&
		((rule->protocol == DP_FWALL_MATCH_ANY_PROTOCOL) || (rule->protocol == protocol))) {
		return true;
	}

	return false;
}

static dp_fwall_rule __rte_always_inline *dp_is_matched_in_fwall_list(struct dp_flow *df_ptr, struct rte_ipv4_hdr *ipv4_hdr, 
											   struct dp_fwall_head *fwall_head, enum dp_fwall_direction dir)
{
	dp_fwall_rule *rule = NULL;

	TAILQ_FOREACH(rule, fwall_head, next_rule)
		if ((dir == rule->dir) && dp_is_rule_matching(rule, df_ptr, ipv4_hdr))
			return rule;

	return rule;
}

enum dp_fwall_action dp_get_firewall_action(struct dp_flow *df_ptr, struct rte_ipv4_hdr *ipv4_hdr, int sender_port_id)
{
	enum dp_fwall_action egress_action = DP_FWALL_DROP, ingress_action = DP_FWALL_DROP;
	dp_fwall_rule *rule;

	if (dp_port_is_pf(df_ptr->nxt_hop)) { /* Outgoing traffic to PF, PF has no Ingress rules */
		rule = dp_is_matched_in_fwall_list(df_ptr, ipv4_hdr, dp_get_fwall_head(sender_port_id), DP_FWALL_EGRESS);
		if (rule)
			return rule->action;
		else
			return DP_FWALL_DROP;
	} else { /* Incoming traffic */
		if (dp_port_is_pf(sender_port_id)) { /* Incoming from PF, PF has no Egress rules */
			egress_action = DP_FWALL_ACCEPT;
		} else { /* Incoming from VF. Check originating VF's Egress rules */
			rule = dp_is_matched_in_fwall_list(df_ptr, ipv4_hdr, dp_get_fwall_head(sender_port_id), DP_FWALL_EGRESS);
			if (rule)
				egress_action = rule->action;
		}

		rule = dp_is_matched_in_fwall_list(df_ptr, ipv4_hdr, dp_get_fwall_head(df_ptr->nxt_hop), DP_FWALL_INGRESS);
		if (rule)
			ingress_action = rule->action;

		if ((ingress_action == DP_FWALL_ACCEPT) && (egress_action == DP_FWALL_ACCEPT))
			return rule->action;
	}

	return DP_FWALL_DROP;
}

void dp_del_all_firewall_rules(int port_id)
{
	dp_fwall_rule *rule;

	if (!dp_get_fwall_head(port_id))
		return;

	while ((rule = TAILQ_FIRST(dp_get_fwall_head(port_id))) != NULL) {
		TAILQ_REMOVE(dp_get_fwall_head(port_id), rule, next_rule);
		rte_free(rule);
	}
}
