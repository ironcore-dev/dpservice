// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#include "dp_firewall.h"
#include <stdbool.h>
#include <rte_malloc.h>
#include "dp_error.h"
#include "dp_lpm.h"
#include "dp_mbuf_dyn.h"
#include "dp_port.h"
#include "grpc/dp_grpc_responder.h"

void dp_init_firewall_rules(struct dp_port *port)
{
	TAILQ_INIT(&port->iface.fwall_head);
	port->iface.fwall_rule_count = 0;
}

int dp_add_firewall_rule(const struct dp_fwall_rule *new_rule, struct dp_port *port)
{
	struct dp_fwall_rule *rule = rte_zmalloc("firewall_rule", sizeof(struct dp_fwall_rule), RTE_CACHE_LINE_SIZE);

	if (!rule)
		return DP_ERROR;

	rte_memcpy(rule, new_rule, sizeof(*rule));
	TAILQ_INSERT_TAIL(&port->iface.fwall_head, rule, next_rule);
	port->iface.fwall_rule_count++;

	return DP_OK;
}


int dp_delete_firewall_rule(const char *rule_id, struct dp_port *port)
{
	struct dp_fwall_head *fwall_head = &port->iface.fwall_head;
	struct dp_fwall_rule *rule, *next_rule;

	for (rule = TAILQ_FIRST(fwall_head); rule != NULL; rule = next_rule) {
		next_rule = TAILQ_NEXT(rule, next_rule);
		if (memcmp(rule->rule_id, rule_id, sizeof(rule->rule_id)) == 0) {
			TAILQ_REMOVE(fwall_head, rule, next_rule);
			rte_free(rule);
			port->iface.fwall_rule_count--;
			return DP_OK;
		}
	}

	return DP_ERROR;
}

struct dp_fwall_rule *dp_get_firewall_rule(const char *rule_id, const struct dp_port *port)
{
	struct dp_fwall_rule *rule;

	TAILQ_FOREACH(rule, &port->iface.fwall_head, next_rule)
		if (memcmp(rule->rule_id, rule_id, sizeof(rule->rule_id)) == 0)
			return rule;

	return NULL;
}

int dp_list_firewall_rules(const struct dp_port *port, struct dp_grpc_responder *responder)
{
	struct dpgrpc_fwrule_info *reply;
	struct dp_fwall_rule *rule;

	dp_grpc_set_multireply(responder, sizeof(*reply));

	TAILQ_FOREACH(rule, &port->iface.fwall_head, next_rule) {
		reply = dp_grpc_add_reply(responder);
		if (!reply)
			return DP_GRPC_ERR_OUT_OF_MEMORY;
		rte_memcpy(&reply->rule, rule, sizeof(reply->rule));
	}

	return DP_GRPC_OK;
}

static __rte_always_inline bool dp_is_rule_matching(const struct dp_fwall_rule *rule,
													const struct dp_flow *df)
{
	uint32_t src_port_lower, src_port_upper;
	uint32_t dst_port_lower, dst_port_upper;
	union dp_ipv6 r_src_ip6;
	union dp_ipv6 r_dest_ip6;
	uint16_t dest_port;
	uint16_t src_port;

	/* Protocol gate: the rule must be a wildcard or match the packet's L4 protocol. */
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
	case IPPROTO_ICMPV6:
		// Till we introduce a dedicated ICMPv6 type for the firewall API, an ICMP rule
		// also matches ICMPv6 packets (type/code are compared as-is).
		if ((rule->protocol != IPPROTO_ICMP) && (rule->protocol != DP_FWALL_MATCH_ANY_PROTOCOL))
			return false;
		break;
	default:
		return false;
	}

	/* IP-prefix checks apply to ALL protocols, before any protocol-specific accept. */
	if (df->l3_type == RTE_ETHER_TYPE_IPV4) {
		if (rule->src_ip.is_v6 || rule->dest_ip.is_v6
			|| (ntohl(df->src.src_addr) & rule->src_mask.ip4) != (rule->src_ip.ipv4 & rule->src_mask.ip4)
			|| (ntohl(df->dst.dst_addr) & rule->dest_mask.ip4) != (rule->dest_ip.ipv4 & rule->dest_mask.ip4))
			return false;
	} else if (df->l3_type == RTE_ETHER_TYPE_IPV6) {
		if (DP_FAILED(dp_ipv6_from_ipaddr(&r_src_ip6, &rule->src_ip))
			|| DP_FAILED(dp_ipv6_from_ipaddr(&r_dest_ip6, &rule->dest_ip))
			|| !dp_masked_ipv6_match(&df->src.src_addr6, &r_src_ip6, &rule->src_mask.ip6)
			|| !dp_masked_ipv6_match(&df->dst.dst_addr6, &r_dest_ip6, &rule->dest_mask.ip6))
			return false;
	} else {
		return false;
	}

	/* Wildcard-protocol (L3) rules match any port / ICMP type once the prefixes matched. */
	/* Their protocol filter is not meaningful (the filter union may alias unrelated bytes). */
	if (rule->protocol == DP_FWALL_MATCH_ANY_PROTOCOL)
		return true;

	/* Protocol-specific matching: port ranges only for TCP/UDP, type/code only for ICMP. */
	switch (df->l4_type) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
		src_port = ntohs(df->l4_info.trans_port.src_port);
		dest_port = ntohs(df->l4_info.trans_port.dst_port);
		src_port_lower = rule->filter.tcp_udp.src_port.lower;
		src_port_upper = rule->filter.tcp_udp.src_port.upper;
		dst_port_lower = rule->filter.tcp_udp.dst_port.lower;
		dst_port_upper = rule->filter.tcp_udp.dst_port.upper;
		return ((src_port_lower == DP_FWALL_MATCH_ANY_PORT) ||
			(src_port >= src_port_lower && src_port <= src_port_upper)) &&
			((dst_port_lower == DP_FWALL_MATCH_ANY_PORT) ||
			(dest_port >= dst_port_lower && dest_port <= dst_port_upper));
	case IPPROTO_ICMP:
	case IPPROTO_ICMPV6:
		return ((rule->filter.icmp.icmp_type == DP_FWALL_MATCH_ANY_ICMP_TYPE) ||
			(df->l4_info.icmp_field.icmp_type == rule->filter.icmp.icmp_type)) &&
			((rule->filter.icmp.icmp_code == DP_FWALL_MATCH_ANY_ICMP_CODE) ||
			(df->l4_info.icmp_field.icmp_code == rule->filter.icmp.icmp_code));
	default:
		return false;
	}
}

static __rte_always_inline struct dp_fwall_rule *dp_is_matched_in_fwall_list(const struct dp_flow *df,
																	  const struct dp_fwall_head *fwall_head,
																	  enum dp_fwall_direction dir,
																	  uint32_t *dir_rule_count)
{
	struct dp_fwall_rule *rule = NULL;

	TAILQ_FOREACH(rule, fwall_head, next_rule) {
		if (dir != rule->dir)
			continue;
		(*dir_rule_count)++;
		if (dp_is_rule_matching(rule, df)) {
			rule->stats.rule_hit++;
			return rule;
		}
	}

	return rule;
}

/* Default action for a given direction is "Accept" when no rule of that direction exists at all. */
/* Once at least one rule for the direction is present, the default becomes "Drop" if no rule matches. */
/* This makes ingress and egress behave symmetrically (implicit allow-all until rules are added). */
static __rte_always_inline enum dp_fwall_action dp_get_directional_action(const struct dp_flow *df,
		const struct dp_fwall_head *fwall_head,
		enum dp_fwall_direction dir)
{
	uint32_t dir_rule_count = 0;
	struct dp_fwall_rule *rule;

	rule = dp_is_matched_in_fwall_list(df, fwall_head, dir, &dir_rule_count);

	if (rule)
		return rule->action;
	else if (dir_rule_count == 0)
		return DP_FWALL_ACCEPT;
	else
		return DP_FWALL_DROP;
}

enum dp_fwall_action dp_get_firewall_action(struct dp_flow *df,
											const struct dp_port *in_port,
											const struct dp_port *out_port)
{
	enum dp_fwall_action egress_action = DP_FWALL_ACCEPT;
	enum dp_fwall_action ingress_action = DP_FWALL_ACCEPT;

	/* A PF holds no firewall rules, so each direction is only evaluated on its VF side.
	 * Both directions are evaluated even when one of them already decided to drop, so that
	 * the per-rule hit counters account for every matching rule.
	 */
	if (!in_port->is_pf)
		egress_action = dp_get_directional_action(df, &in_port->iface.fwall_head, DP_FWALL_EGRESS);
	if (!out_port->is_pf)
		ingress_action = dp_get_directional_action(df, &out_port->iface.fwall_head, DP_FWALL_INGRESS);

	/* Each side is enforced independently, and only if its own firewall is enabled */
	if (egress_action == DP_FWALL_DROP && in_port->iface.fwall_state == DP_FWALL_ENABLED)
		return DP_FWALL_DROP;

	if (ingress_action == DP_FWALL_DROP && out_port->iface.fwall_state == DP_FWALL_ENABLED)
		return DP_FWALL_DROP;

	return DP_FWALL_ACCEPT;
}

void dp_del_all_firewall_rules(struct dp_port *port)
{
	struct dp_fwall_head *fwall_head = &port->iface.fwall_head;
	struct dp_fwall_rule *rule;

	while ((rule = TAILQ_FIRST(fwall_head)) != NULL) {
		TAILQ_REMOVE(fwall_head, rule, next_rule);
		rte_free(rule);
	}
	port->iface.fwall_rule_count = 0;
}
