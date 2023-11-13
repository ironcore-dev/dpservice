#include "dp_firewall.h"
#include <stdbool.h>
#include "dp_error.h"
#include "dp_lpm.h"
#include "dp_mbuf_dyn.h"
#include "dp_port.h"
#include "grpc/dp_grpc_responder.h"

void dp_init_firewall_rules(struct dp_port *port)
{
	TAILQ_INIT(&port->vm.fwall_head);
}

int dp_add_firewall_rule(const struct dp_fwall_rule *new_rule, struct dp_port *port)
{
	struct dp_fwall_rule *rule = rte_zmalloc("firewall_rule", sizeof(struct dp_fwall_rule), RTE_CACHE_LINE_SIZE);

	if (!rule)
		return DP_ERROR;

	*rule = *new_rule;
	TAILQ_INSERT_TAIL(&port->vm.fwall_head, rule, next_rule);

	return DP_OK;
}


int dp_delete_firewall_rule(const char *rule_id, struct dp_port *port)
{
	struct dp_fwall_head *fwall_head = &port->vm.fwall_head;
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

struct dp_fwall_rule *dp_get_firewall_rule(const char *rule_id, const struct dp_port *port)
{
	struct dp_fwall_rule *rule;

	TAILQ_FOREACH(rule, &port->vm.fwall_head, next_rule)
		if (memcmp(rule->rule_id, rule_id, sizeof(rule->rule_id)) == 0)
			return rule;

	return NULL;
}

int dp_list_firewall_rules(const struct dp_port *port, struct dp_grpc_responder *responder)
{
	struct dpgrpc_fwrule_info *reply;
	struct dp_fwall_rule *rule;

	dp_grpc_set_multireply(responder, sizeof(*reply));

	TAILQ_FOREACH(rule, &port->vm.fwall_head, next_rule) {
		reply = dp_grpc_add_reply(responder);
		if (!reply)
			return DP_GRPC_ERR_OUT_OF_MEMORY;
		reply->rule = *rule;
	}

	return DP_GRPC_OK;
}

static __rte_always_inline bool dp_is_rule_matching(const struct dp_fwall_rule *rule,
													const struct dp_flow *df)
{
	uint32_t dest_ip = ntohl(df->dst.dst_addr);
	uint32_t src_ip = ntohl(df->src.src_addr);
	uint32_t src_port_lower, src_port_upper = 0;
	uint32_t dst_port_lower, dst_port_upper = 0;
	uint32_t r_dest_ip = rule->dest_ip;
	uint32_t r_src_ip = rule->src_ip;
	uint8_t protocol = df->l4_type;
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
		if (((rule->filter.icmp.icmp_type == DP_FWALL_MATCH_ANY_ICMP_TYPE) ||
			(df->l4_info.icmp_field.icmp_type == rule->filter.icmp.icmp_type)) &&
			((rule->filter.icmp.icmp_code == DP_FWALL_MATCH_ANY_ICMP_CODE) ||
			(df->l4_info.icmp_field.icmp_code == rule->filter.icmp.icmp_code)) &&
			((rule->protocol == DP_FWALL_MATCH_ANY_PROTOCOL) || (rule->protocol == protocol)))
			return true;
		break;
	default:
		return false;
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

static __rte_always_inline struct dp_fwall_rule *dp_is_matched_in_fwall_list(const struct dp_flow *df,
																	  const struct dp_fwall_head *fwall_head,
																	  enum dp_fwall_direction dir,
																	  uint32_t *egress_rule_count)
{
	struct dp_fwall_rule *rule = NULL;

	TAILQ_FOREACH(rule, fwall_head, next_rule) {
		if (rule->dir == DP_FWALL_EGRESS)
			(*egress_rule_count)++;
		if ((dir == rule->dir) && dp_is_rule_matching(rule, df))
			return rule;
	}

	return rule;
}

/* Egress default for the traffic originating from VFs is "Accept", when no rule matches. If there is at least one */
/* Egress rule than the default action becomes drop, if there is no rule matching */
/* Another approach here could be to install a default egress rule for each interface which allows everything */
static __rte_always_inline enum dp_fwall_action dp_get_egress_action(const struct dp_flow *df,
																	 const struct dp_fwall_head *fwall_head)
{
	uint32_t egress_rule_count = 0;
	struct dp_fwall_rule *rule;

	rule = dp_is_matched_in_fwall_list(df, fwall_head, DP_FWALL_EGRESS, &egress_rule_count);

	if (rule)
		return rule->action;
	else if (egress_rule_count == 0)
		return DP_FWALL_ACCEPT;
	else
		return DP_FWALL_DROP;
}

enum dp_fwall_action dp_get_firewall_action(struct dp_flow *df,
											const struct dp_port *src_port,
											const struct dp_port *dst_port)
{
	enum dp_fwall_action egress_action;
	struct dp_fwall_rule *rule;

	/* Outgoing traffic to PF (VF Egress, PF Ingress), PF has no Ingress rules */
	if (dst_port->is_pf)
		return dp_get_egress_action(df, &src_port->vm.fwall_head);

	/* Incoming from PF, PF has no Egress rules */
	if (src_port->is_pf)
		egress_action = DP_FWALL_ACCEPT;
	/* Incoming from VF. Check originating VF's Egress rules */
	else
		egress_action = dp_get_egress_action(df, &src_port->vm.fwall_head);

	if (egress_action != DP_FWALL_ACCEPT)
		return DP_FWALL_DROP;

	rule = dp_is_matched_in_fwall_list(df, &dst_port->vm.fwall_head, DP_FWALL_INGRESS, NULL);
	if (!rule || rule->action != DP_FWALL_ACCEPT)
		return DP_FWALL_DROP;

	return DP_FWALL_ACCEPT;
}

void dp_del_all_firewall_rules(struct dp_port *port)
{
	struct dp_fwall_head *fwall_head = &port->vm.fwall_head;
	struct dp_fwall_rule *rule;

	while ((rule = TAILQ_FIRST(fwall_head)) != NULL) {
		TAILQ_REMOVE(fwall_head, rule, next_rule);
		rte_free(rule);
	}
}
