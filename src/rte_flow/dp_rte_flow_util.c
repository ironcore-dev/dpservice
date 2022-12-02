#include "rte_flow/dp_rte_flow_util.h"
#include "rte_flow/dp_rte_flow_traffic_forward.h"

__rte_always_inline int dp_install_protection_drop(struct rte_mbuf *m, struct dp_flow *df)
{
	struct underlay_conf *u_conf = get_underlay_conf();

	struct rte_flow_attr attr;

	struct rte_flow_item pattern[DP_TUNN_OPS_OFFLOAD_MAX_PATTERN];
	int pattern_cnt = 0;
	struct rte_flow_action action[2];
	int action_cnt = 0;

	memset(pattern, 0, sizeof(pattern));
	memset(action, 0, sizeof(action));

	// create flow match patterns -- eth
	struct rte_flow_item_eth eth_spec;
	struct rte_flow_item_eth eth_mask;

	pattern_cnt = insert_ethernet_match_pattern(pattern, pattern_cnt,
												&eth_spec, &eth_mask,
												NULL, 0, NULL, 0,
												htons(df->tun_info.l3_type));

	// create flow match patterns -- ipv6
	struct rte_flow_item_ipv6 ipv6_spec;
	struct rte_flow_item_ipv6 ipv6_mask;

	pattern_cnt = insert_ipv6_match_pattern(pattern, pattern_cnt,
											&ipv6_spec, &ipv6_mask,
											NULL, 0,
											df->tun_info.ul_dst_addr6, sizeof(df->tun_info.ul_dst_addr6),
											df->tun_info.proto_id);

	if (get_overlay_type() == DP_FLOW_OVERLAY_TYPE_GENEVE) {

		// create flow match patterns -- udp
		struct rte_flow_item_udp udp_spec;
		struct rte_flow_item_udp udp_mask;

		pattern_cnt = insert_udp_match_pattern(pattern, pattern_cnt,
											   &udp_spec, &udp_mask,
											   0, htons(u_conf->dst_port));

		// create flow match patterns -- geneve
		struct rte_flow_item_geneve gen_spec;
		struct rte_flow_item_geneve gen_mask;

		pattern_cnt = insert_geneve_match_pattern(pattern, pattern_cnt,
												  &gen_spec, &gen_mask,
												  df->l3_type, &df->tun_info.dst_vni);
	}

	// create flow match patterns -- inner packet, ipv6 or ipv4
	struct rte_flow_item_ipv6 ol_ipv6_spec;
	struct rte_flow_item_ipv6 ol_ipv6_mask;

	struct rte_flow_item_ipv4 ol_ipv4_spec;
	struct rte_flow_item_ipv4 ol_ipv4_mask;

	if (df->l3_type == RTE_ETHER_TYPE_IPV6) {
		pattern_cnt = insert_ipv6_match_pattern(pattern, pattern_cnt,
												&ol_ipv6_spec, &ol_ipv6_mask,
												NULL, 0,
												df->dst.dst_addr6, sizeof(ol_ipv6_spec.hdr.dst_addr),
												df->l4_type);

	} else {
		pattern_cnt = insert_ipv4_match_pattern(pattern, pattern_cnt,
												&ol_ipv4_spec, &ol_ipv4_mask,
												df, DP_IS_DST);

	}

	// create flow match patterns -- inner packet, tcp, udp or icmp/icmpv6
	struct rte_flow_item_tcp tcp_spec;
	struct rte_flow_item_tcp tcp_mask;

	if (df->l4_type == DP_IP_PROTO_TCP) {
		pattern_cnt = insert_tcp_match_pattern(pattern, pattern_cnt,
											   &tcp_spec, &tcp_mask,
											   df->src_port, df->dst_port);

	}

	struct rte_flow_item_udp udp_spec;
	struct rte_flow_item_udp udp_mask;

	if (df->l4_type == DP_IP_PROTO_UDP) {
		pattern_cnt = insert_udp_match_pattern(pattern, pattern_cnt,
											   &udp_spec, &udp_mask,
											   df->src_port, df->dst_port);
	}

	struct rte_flow_item_icmp icmp_spec;
	struct rte_flow_item_icmp icmp_mask;

	if (df->l4_type == DP_IP_PROTO_ICMP) {
		pattern_cnt = insert_icmp_match_pattern(pattern, pattern_cnt,
												&icmp_spec, &icmp_mask,
												df->icmp_type);
	}

	struct rte_flow_item_icmp6 icmp6_spec;
	struct rte_flow_item_icmp6 icmp6_mask;

	if (df->l4_type == DP_IP_PROTO_ICMPV6) {
		pattern_cnt = insert_icmpv6_match_pattern(pattern, pattern_cnt,
												  &icmp6_spec, &icmp6_mask,
												  df->icmp_type);
	}

	// create flow match patterns -- end
	pattern_cnt = insert_end_match_pattern(pattern, pattern_cnt);


	// create action -- drop
	action_cnt = create_drop_action(action, action_cnt);

	// create flow action -- age
	struct flow_age_ctx *agectx = rte_zmalloc("age_ctx", sizeof(struct flow_age_ctx), RTE_CACHE_LINE_SIZE);
	struct rte_flow_action_age flow_age;

	if (!agectx)
		return 0;

	action_cnt = create_flow_age_action(action, action_cnt,
											&flow_age, 3, agectx);

	// create flow action -- end
	action_cnt = create_end_action(action, action_cnt);

	// validate and install rte flow
	create_rte_flow_rule_attr(&attr, 0, 0, 1, 0, 1);
	struct rte_flow *flow = NULL;

	flow = validate_and_install_rte_flow(m->port, &attr, pattern, action, df);
	if (!flow) {
		free_allocated_agectx(agectx);
		return 0;
	}
	// config the content of agectx
	config_allocated_agectx(agectx, m->port, df, flow);
	return 1;
}