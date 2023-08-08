#include "rte_flow/dp_rte_flow_traffic_forward.h"
#include "dp_nat.h"
#include "dp_log.h"
#include "dp_error.h"

static const struct rte_flow_attr dp_flow_attr_ingress = {
	.group = 0,
	.priority = 0,
	.ingress = 1,
	.egress = 0,
	.transfer = 0,
};

static const struct rte_flow_attr dp_flow_attr_egress = {
	.group = 0,
	.priority = 0,
	.ingress = 0,
	.egress = 1,
	.transfer = 0,
};

static const struct rte_flow_attr dp_flow_attr_transfer = {
	.group = 0,
	.priority = 0,
#ifdef ENABLE_DPDK_22_11
	.ingress = 0,
#else
	.ingress = 1,
#endif
	.egress = 0,
	.transfer = 1,
};

static __rte_always_inline int dp_install_rte_flow_with_age(uint16_t port_id,
															const struct rte_flow_attr *attr,
															const struct rte_flow_item pattern[],
															const struct rte_flow_action actions[],
															struct flow_value *conntrack,
															struct flow_age_ctx *agectx)
{
	struct rte_flow *flow;

	flow = dp_install_rte_flow(port_id, attr, pattern, actions);
	if (!flow)
		return DP_ERROR;

	agectx->cntrack = conntrack;
	agectx->rte_flow = flow;
	agectx->port_id = port_id;
	dp_ref_inc(&conntrack->ref_count);
	return DP_OK;
}

static __rte_always_inline int dp_install_rte_flow_with_indirect(uint16_t port_id,
																 const struct rte_flow_attr *attr,
																 const struct rte_flow_item pattern[],
																 const struct rte_flow_action actions[],
																 const struct rte_flow_action *age_action,
																 const struct dp_flow *df,
																 struct flow_age_ctx *agectx)
{
	if (df->l4_type == IPPROTO_TCP)
		if (DP_FAILED(dp_create_age_indirect_action(port_id, attr, age_action, df->conntrack, agectx)))
			return DP_ERROR;

	return dp_install_rte_flow_with_age(port_id, attr, pattern, actions, df->conntrack, agectx);
}

static __rte_always_inline int dp_offload_handle_tunnel_encap_traffic(struct rte_mbuf *m, struct dp_flow *df)
{
	struct underlay_conf *u_conf = get_underlay_conf();
	bool cross_pf_port = df->nxt_hop == dp_port_get_pf0_id() ? false : true;

	struct rte_flow_item pattern[DP_TUNN_OPS_OFFLOAD_MAX_PATTERN];
	int pattern_cnt = 0;
	struct rte_flow_item hairpin_pattern[DP_TUNN_OPS_OFFLOAD_MAX_PATTERN];
	int hairpin_pattern_cnt = 0;
	struct rte_flow_action action[DP_TUNN_OPS_OFFLOAD_MAX_ACTION];
	int action_cnt = 0;
	struct rte_flow_action hairpin_action[DP_TUNN_OPS_OFFLOAD_MAX_ACTION];
	int hairpin_action_cnt = 0;

	const struct rte_flow_action *age_action;

	memset(pattern, 0, sizeof(pattern));
	memset(hairpin_pattern, 0, sizeof(hairpin_pattern));
	memset(action, 0, sizeof(action));
	memset(hairpin_action, 0, sizeof(hairpin_action));

	uint8_t vni_in_mac_addr[RTE_ETHER_ADDR_LEN];

	memset(vni_in_mac_addr, 0, sizeof(vni_in_mac_addr));
	memcpy(vni_in_mac_addr, &df->tun_info.dst_vni, 4);

	// create flow match patterns -- eth, for matching vf packets
	struct rte_flow_item_eth ol_eth_spec;
	struct rte_flow_item_eth ol_eth_mask;

	if (cross_pf_port)
		hairpin_pattern_cnt = insert_ethernet_match_pattern(hairpin_pattern, hairpin_pattern_cnt,
												&ol_eth_spec, &ol_eth_mask,
												NULL, 0, NULL, 0,
												htons(df->l3_type));

	// create flow match patterns -- eth, for matching modified vf packets embedded with vni info
	struct rte_flow_item_eth eth_spec;
	struct rte_flow_item_eth eth_mask;
	struct rte_ether_addr modified_eth_dst_addr;

	memcpy(modified_eth_dst_addr.addr_bytes, vni_in_mac_addr, sizeof(struct rte_ether_addr));

	if (cross_pf_port)
		pattern_cnt = insert_ethernet_match_pattern(pattern, pattern_cnt,
													&eth_spec, &eth_mask,
													NULL, 0, &modified_eth_dst_addr, sizeof(struct rte_ether_addr),
													htons(df->l3_type));
	else
		pattern_cnt = insert_ethernet_match_pattern(pattern, pattern_cnt,
													&eth_spec, &eth_mask,
													NULL, 0, NULL, 0,
													htons(df->l3_type));

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
												NULL, 0,
												&df->dst.dst_addr, sizeof(ol_ipv4_spec.hdr.dst_addr),
												df->l4_type);
	}

	if (cross_pf_port)
		hairpin_pattern[hairpin_pattern_cnt++] = pattern[pattern_cnt-1];

	// create flow match patterns -- inner packet, tcp, udp or icmp/icmpv6
	struct rte_flow_item_tcp tcp_spec;
	struct rte_flow_item_tcp tcp_mask;
	struct rte_flow_item_udp udp_spec;
	struct rte_flow_item_udp udp_mask;
	struct rte_flow_item_icmp icmp_spec;
	struct rte_flow_item_icmp icmp_mask;
	struct rte_flow_item_icmp6 icmp6_spec;
	struct rte_flow_item_icmp6 icmp6_mask;

	if (df->l4_type == DP_IP_PROTO_TCP) {
		pattern_cnt = insert_tcp_match_pattern(pattern, pattern_cnt,
											   &tcp_spec, &tcp_mask,
											   df->l4_info.trans_port.src_port, df->l4_info.trans_port.dst_port,
											   DP_RTE_TCP_CNTL_FLAGS);
	} else if (df->l4_type == DP_IP_PROTO_UDP) {
		pattern_cnt = insert_udp_match_pattern(pattern, pattern_cnt,
											   &udp_spec, &udp_mask,
											   df->l4_info.trans_port.src_port, df->l4_info.trans_port.dst_port);
	} else if (df->l4_type == DP_IP_PROTO_ICMP) {
		pattern_cnt = insert_icmp_match_pattern(pattern, pattern_cnt,
												&icmp_spec, &icmp_mask,
												df->l4_info.icmp_field.icmp_type);
	} else if (df->l4_type == DP_IP_PROTO_ICMPV6) {
		pattern_cnt = insert_icmpv6_match_pattern(pattern, pattern_cnt,
												  &icmp6_spec, &icmp6_mask,
												  df->l4_info.icmp_field.icmp_type);
	}

	if (cross_pf_port)
		hairpin_pattern[hairpin_pattern_cnt++] = pattern[pattern_cnt-1];

	// create flow match patterns -- end
	if (cross_pf_port)
		hairpin_pattern_cnt = insert_end_match_pattern(hairpin_pattern, hairpin_pattern_cnt);

	pattern_cnt = insert_end_match_pattern(pattern, pattern_cnt);


	/* First, install a flow rule to modify mac addr to embed vni info and move packet to hairpin rxq */
	if (cross_pf_port) {
		struct rte_flow_action_set_mac set_mac_action;
		struct rte_flow_action_queue queue_action;
		struct rte_flow_action_age flow_age;
		struct rte_ether_addr	e_addr;

		memcpy(e_addr.addr_bytes, vni_in_mac_addr, sizeof(RTE_ETHER_ADDR_LEN));
		uint16_t hairpin_rx_queue_id = DP_NR_STD_RX_QUEUES;

		// create flow action -- set mac
		hairpin_action_cnt = create_dst_mac_set_action(hairpin_action, hairpin_action_cnt, &set_mac_action, &e_addr);
		// create flow action -- move pkt to rx hairpin queue
		hairpin_action_cnt = create_redirect_queue_action(hairpin_action, hairpin_action_cnt, &queue_action, hairpin_rx_queue_id);

		// create flow action -- age
		struct flow_age_ctx *hairpin_agectx = rte_zmalloc("age_ctx", sizeof(struct flow_age_ctx), RTE_CACHE_LINE_SIZE);

		if (!hairpin_agectx) {
			DPS_LOG_ERR("Failed to allocate cross-port encap age_ctx");
			return DP_ERROR;
		}
		age_action = &hairpin_action[hairpin_action_cnt];
		hairpin_action_cnt = create_flow_age_action(hairpin_action, hairpin_action_cnt,
										&flow_age, df->conntrack->timeout_value, hairpin_agectx);

		// create flow action -- end
		hairpin_action_cnt = create_end_action(hairpin_action, hairpin_action_cnt);

		if (DP_FAILED(dp_install_rte_flow_with_indirect(m->port, &dp_flow_attr_ingress,
														hairpin_pattern, hairpin_action,
														age_action, df, hairpin_agectx))
		) {
			free_allocated_agectx(hairpin_agectx);
			DPS_LOG_ERR("Failed to install hairpin queue flow rule on VF", DP_LOG_PORTID(m->port));
		}
		DPS_LOG_DEBUG("Installed hairpin queue flow rule", DP_LOG_PORTID(m->port));
	}

	// replace source ip if vip-nat/network-nat is enabled
	struct rte_flow_action_set_ipv4 set_ipv4;
	if (df->flags.nat == DP_NAT_CHG_SRC_IP)
		action_cnt = create_ipv4_set_action(action, action_cnt,
										    &set_ipv4, df->nat_addr, DP_IS_SRC);

	// replace source port if network-nat is enabled
	struct rte_flow_action_set_tp set_tp;

	if (df->flags.nat == DP_NAT_CHG_SRC_IP && df->conntrack->nf_info.nat_type == DP_FLOW_NAT_TYPE_NETWORK_LOCAL)
		action_cnt = create_trans_proto_set_action(action, action_cnt,
										    &set_tp, df->nat_port, DP_IS_SRC);

	// create flow action -- raw decap
	struct rte_flow_action_raw_decap raw_decap;

	action_cnt = create_raw_decap_action(action, action_cnt,
										 &raw_decap, NULL, sizeof(struct rte_ether_hdr));

	// create flow action -- raw encap
	uint8_t encap_hdr[DP_TUNN_IPIP_ENCAP_SIZE];

	memset(encap_hdr, 0, DP_TUNN_IPIP_ENCAP_SIZE);

	struct rte_flow_action_raw_encap raw_encap;

	struct rte_ether_hdr *new_eth_hdr = (struct rte_ether_hdr *)encap_hdr;

	rte_ether_addr_copy(dp_get_neigh_mac(df->nxt_hop), &new_eth_hdr->dst_addr);
	rte_ether_addr_copy(dp_get_mac(df->nxt_hop), &new_eth_hdr->src_addr);
	new_eth_hdr->ether_type = htons(RTE_ETHER_TYPE_IPV6);

	struct rte_ipv6_hdr *new_ipv6_hdr = (struct rte_ipv6_hdr *)(&encap_hdr[sizeof(struct rte_ether_hdr)]);

	new_ipv6_hdr->vtc_flow = htonl(DP_IP6_VTC_FLOW);
	new_ipv6_hdr->hop_limits = DP_IP6_HOP_LIMIT;
	new_ipv6_hdr->proto = df->tun_info.proto_id;
	rte_memcpy(new_ipv6_hdr->src_addr, u_conf->src_ip6, sizeof(new_ipv6_hdr->src_addr));
	rte_memcpy(new_ipv6_hdr->dst_addr, df->tun_info.ul_dst_addr6, sizeof(new_ipv6_hdr->dst_addr));

	action_cnt = create_raw_encap_action(action, action_cnt,
										 &raw_encap, encap_hdr, DP_TUNN_IPIP_ENCAP_SIZE);

	// create flow action -- age
	struct rte_flow_action_age flow_age;
	struct flow_age_ctx *agectx = rte_zmalloc("age_ctx", sizeof(struct flow_age_ctx), RTE_CACHE_LINE_SIZE);

	if (!agectx) {
		DPS_LOG_ERR("Failed to allocate encap age_ctx");
		return DP_ERROR;
	}
	age_action = &action[action_cnt];
	action_cnt = create_flow_age_action(action, action_cnt,
										&flow_age, df->conntrack->timeout_value, agectx);

	// create flow action -- send to port
	struct rte_flow_action_port_id send_to_port;

	if (!cross_pf_port)
		action_cnt = create_send_to_port_action(action, action_cnt,
												&send_to_port, df->nxt_hop);

	// create flow action -- end
	action_cnt = create_end_action(action, action_cnt);

	// validate and install rte flow
	const struct rte_flow_attr *attr;
	uint16_t t_port_id;

	if (cross_pf_port) {
		attr = &dp_flow_attr_egress;
		t_port_id = dp_port_get_pf1_id();
	} else {
		attr = &dp_flow_attr_transfer;
		t_port_id = m->port;
	}

	if (DP_FAILED(dp_install_rte_flow_with_indirect(t_port_id, attr,
													pattern, action,
													age_action, df, agectx))
	) {
		free_allocated_agectx(agectx);
		DPS_LOG_ERR("Failed to install encap flow rule on PF", DP_LOG_PORTID(t_port_id));
	}
	DPS_LOG_DEBUG("Installed encap flow rule on PF", DP_LOG_PORTID(t_port_id));

	return DP_OK;
}

static __rte_always_inline int dp_offload_handle_tunnel_decap_traffic(struct rte_mbuf *m, struct dp_flow *df)
{
	bool cross_pf_port;

	if (m->port == dp_port_get_pf0_id()) {
		cross_pf_port = false;
		df->conntrack->incoming_flow_offloaded_flag.pf0 = true;
	} else {
		cross_pf_port = true;
		df->conntrack->incoming_flow_offloaded_flag.pf1 = true;
	}

	int hairpin_pattern_cnt = 0;
	struct rte_flow_item pattern[DP_TUNN_OPS_OFFLOAD_MAX_PATTERN];
	int pattern_cnt = 0;
	struct rte_flow_item hairpin_pattern[DP_TUNN_OPS_OFFLOAD_MAX_PATTERN];
	struct rte_flow_action action[DP_TUNN_OPS_OFFLOAD_MAX_ACTION];
	int action_cnt = 0;
	const struct rte_flow_action *age_action;

#ifndef ENABLE_DPDK_22_11
	struct rte_flow_action hairpin_action[DP_TUNN_OPS_OFFLOAD_MAX_ACTION];
	int hairpin_action_cnt = 0;

	memset(hairpin_pattern, 0, sizeof(hairpin_pattern));
	memset(hairpin_action, 0, sizeof(hairpin_action));
#endif

	memset(pattern, 0, sizeof(pattern));
	memset(action, 0, sizeof(action));

	uint8_t eth_hdr[sizeof(struct rte_ether_hdr)];
	struct rte_ether_hdr *new_eth_hdr = (struct rte_ether_hdr *)eth_hdr;

	rte_ether_addr_copy(dp_get_neigh_mac(df->nxt_hop), &new_eth_hdr->dst_addr);
	rte_ether_addr_copy(dp_get_mac(df->nxt_hop), &new_eth_hdr->src_addr);
	new_eth_hdr->ether_type = htons(df->l3_type);

	struct rte_flow_item_eth ol_eth_spec;
	struct rte_flow_item_eth ol_eth_mask;

	if (cross_pf_port)
		hairpin_pattern_cnt = insert_ethernet_match_pattern(hairpin_pattern, hairpin_pattern_cnt,
														&ol_eth_spec, &ol_eth_mask,
														&new_eth_hdr->src_addr, sizeof(struct rte_ether_addr),
														&new_eth_hdr->dst_addr, sizeof(struct rte_ether_addr),
														new_eth_hdr->ether_type);

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

	// restore the actual incoming pkt's ipv6 dst addr
	if (dp_get_pkt_mark(m)->flags.is_recirc)
		rte_memcpy(df->tun_info.ul_dst_addr6, df->tun_info.ul_src_addr6, sizeof(df->tun_info.ul_dst_addr6));

	pattern_cnt = insert_ipv6_match_pattern(pattern, pattern_cnt,
											&ipv6_spec, &ipv6_mask,
											NULL, 0,
											df->tun_info.ul_dst_addr6, sizeof(df->tun_info.ul_dst_addr6),
											df->tun_info.proto_id);

	// create flow match patterns -- inner packet, ipv6 or ipv4
	struct rte_flow_item_ipv6 ol_ipv6_spec;
	struct rte_flow_item_ipv6 ol_ipv6_mask;
	struct rte_flow_item_ipv4 ol_ipv4_spec;
	struct rte_flow_item_ipv4 ol_ipv4_mask;
	rte_be32_t actual_ol_ipv4_addr;

	if (df->l3_type == RTE_ETHER_TYPE_IPV6) {
		pattern_cnt = insert_ipv6_match_pattern(pattern, pattern_cnt,
												&ol_ipv6_spec, &ol_ipv6_mask,
												NULL, 0,
												df->dst.dst_addr6, sizeof(ol_ipv6_spec.hdr.dst_addr),
												df->l4_type);
	} else {
		// if this flow is the returned vip-natted flow, inner ipv4 addr shall be the VIP (NAT addr)
		if (df->flags.nat == DP_NAT_CHG_DST_IP)
			actual_ol_ipv4_addr = df->nat_addr;
		else
			actual_ol_ipv4_addr = df->dst.dst_addr;

		pattern_cnt = insert_ipv4_match_pattern(pattern, pattern_cnt,
												&ol_ipv4_spec, &ol_ipv4_mask,
												NULL, 0,
												&actual_ol_ipv4_addr, sizeof(actual_ol_ipv4_addr),
												df->l4_type);
	}

	if (cross_pf_port)
		hairpin_pattern[hairpin_pattern_cnt++] = pattern[pattern_cnt-1];

	// create flow match patterns -- inner packet, tcp, udp or icmp/icmpv6
	struct rte_flow_item_tcp tcp_spec;
	struct rte_flow_item_tcp tcp_mask;
	struct rte_flow_item_udp udp_spec;
	struct rte_flow_item_udp udp_mask;
	struct rte_flow_item_icmp icmp_spec;
	struct rte_flow_item_icmp icmp_mask;
	struct rte_flow_item_icmp6 icmp6_spec;
	struct rte_flow_item_icmp6 icmp6_mask;

	if (df->l4_type == DP_IP_PROTO_TCP) {
		pattern_cnt = insert_tcp_match_pattern(pattern, pattern_cnt,
											   &tcp_spec, &tcp_mask,
											   df->l4_info.trans_port.src_port, df->l4_info.trans_port.dst_port,
											   DP_RTE_TCP_CNTL_FLAGS);
	} else if (df->l4_type == DP_IP_PROTO_UDP) {
		pattern_cnt = insert_udp_match_pattern(pattern, pattern_cnt,
											   &udp_spec, &udp_mask,
											   df->l4_info.trans_port.src_port, df->l4_info.trans_port.dst_port);
	} else if (df->l4_type == DP_IP_PROTO_ICMP) {
		pattern_cnt = insert_icmp_match_pattern(pattern, pattern_cnt,
												&icmp_spec, &icmp_mask,
												df->l4_info.icmp_field.icmp_type);
	} else if (df->l4_type == DP_IP_PROTO_ICMPV6) {
		pattern_cnt = insert_icmpv6_match_pattern(pattern, pattern_cnt,
												  &icmp6_spec, &icmp6_mask,
												  df->l4_info.icmp_field.icmp_type);
	}

	if (cross_pf_port)
		hairpin_pattern[hairpin_pattern_cnt++] = pattern[pattern_cnt-1];

	// create flow match patterns -- end
	pattern_cnt = insert_end_match_pattern(pattern, pattern_cnt);
	if (cross_pf_port)
		hairpin_pattern_cnt = insert_end_match_pattern(hairpin_pattern, hairpin_pattern_cnt);


	// create flow action -- raw decap
	struct rte_flow_action_raw_decap raw_decap;

	action_cnt = create_raw_decap_action(action, action_cnt, &raw_decap, NULL, DP_TUNN_IPIP_ENCAP_SIZE);

	// create flow action -- raw encap
	struct rte_flow_action_raw_encap raw_encap;

	action_cnt = create_raw_encap_action(action, action_cnt,
										 &raw_encap, eth_hdr, sizeof(struct rte_ether_hdr));

	// replace dst ip if vip-nat/network-nat is enabled
	struct rte_flow_action_set_ipv4 set_ipv4;
	if (df->flags.nat == DP_NAT_CHG_DST_IP)
		action_cnt = create_ipv4_set_action(action, action_cnt,
										    &set_ipv4, df->dst.dst_addr, DP_IS_DST);

	// replace dst port if network-nat is enabled
	struct rte_flow_action_set_tp set_tp;

	if (df->flags.nat == DP_NAT_CHG_DST_IP && df->conntrack->nf_info.nat_type == DP_FLOW_NAT_TYPE_NETWORK_LOCAL)
		action_cnt = create_trans_proto_set_action(action, action_cnt,
										    &set_tp, df->conntrack->flow_key[DP_FLOW_DIR_ORG].src.port_src, DP_IS_DST);

	// create flow action -- age
	struct rte_flow_action_age flow_age;
	struct flow_age_ctx *agectx = rte_zmalloc("age_ctx", sizeof(struct flow_age_ctx), RTE_CACHE_LINE_SIZE);

	if (!agectx) {
		DPS_LOG_ERR("Cannot allocate tunnel decap flow age_ctx");
		return DP_ERROR;
	}

	age_action = &action[action_cnt];
	action_cnt = create_flow_age_action(action, action_cnt,
											&flow_age, df->conntrack->timeout_value, agectx);

	// move this packet to the right hairpin rx queue of pf, so as to be moved to vf
	struct rte_flow_action_queue queue_action;
	struct rte_flow_action_port_id send_to_port;

	if (cross_pf_port) {
		struct dp_port *port = dp_port_get_vf((uint16_t)df->nxt_hop);
		uint16_t hairpin_rx_queue_id;

		if (!port) {
			DPS_LOG_WARNING("Port not registered in service", DP_LOG_PORTID(df->nxt_hop));
			hairpin_rx_queue_id = 0;
		} else {
			// pf's rx hairpin queue for vf starts from index 2. (0: normal rxq, 1: hairpin rxq for another pf.)
			hairpin_rx_queue_id = DP_NR_RESERVED_RX_QUEUES - 1 + port->peer_pf_hairpin_tx_rx_queue_offset;
		}
		action_cnt = create_redirect_queue_action(action, action_cnt, &queue_action, hairpin_rx_queue_id);
	} else {
		// create flow action -- send to port
		action_cnt = create_send_to_port_action(action, action_cnt,
											&send_to_port, df->nxt_hop);
	}

	// create flow action -- end
	action_cnt = create_end_action(action, action_cnt);

	// validate and install rte flow
	const struct rte_flow_attr *attr;

	attr = cross_pf_port ? &dp_flow_attr_ingress : &dp_flow_attr_transfer;

	if (DP_FAILED(dp_install_rte_flow_with_indirect(m->port, attr,
													pattern, action,
													age_action, df, agectx))
	) {
		free_allocated_agectx(agectx);
		DPS_LOG_ERR("Failed to install normal decap flow rule on PF", DP_LOG_PORTID(m->port));
	}
	DPS_LOG_DEBUG("Installed normal decap flow rule on PF", DP_LOG_PORTID(m->port));

#ifndef ENABLE_DPDK_22_11
	// create flow action -- set dst mac
	/* This redundant action is needed to make hairpin work */
	struct rte_flow_action_set_mac set_dst_mac;
	struct rte_flow_action_age hairpin_flow_age;

	if (cross_pf_port) {
		hairpin_action_cnt = create_dst_mac_set_action(hairpin_action, hairpin_action_cnt,
											&set_dst_mac, &new_eth_hdr->dst_addr);
		// create flow action -- age
		struct flow_age_ctx *hairpin_agectx = rte_zmalloc("age_ctx", sizeof(struct flow_age_ctx), RTE_CACHE_LINE_SIZE);

		if (!hairpin_agectx) {
			DPS_LOG_ERR("Cannot allocate hairpin queue flow age_ctx");
			return DP_ERROR;
		}
		age_action = &hairpin_action[hairpin_action_cnt];
		hairpin_action_cnt = create_flow_age_action(hairpin_action, hairpin_action_cnt,
											&hairpin_flow_age, df->conntrack->timeout_value, hairpin_agectx);

		// create flow action -- end
		hairpin_action_cnt = create_end_action(hairpin_action, hairpin_action_cnt);

		if (DP_FAILED(dp_install_rte_flow_with_indirect(df->nxt_hop, &dp_flow_attr_egress,
														pattern, hairpin_action,
														age_action, df, hairpin_agectx))
		) {
			free_allocated_agectx(hairpin_agectx);
			DPS_LOG_ERR("Failed to install hairpin queue flow rule on VF", DP_LOG_PORTID(df->nxt_hop));
		}
		DPS_LOG_DEBUG("Installed hairpin queue flow rule on VF", DP_LOG_PORTID(df->nxt_hop));
	}
#endif

	return DP_OK;
}

static __rte_always_inline int dp_offload_handle_local_traffic(struct rte_mbuf *m, struct dp_flow *df)
{
	struct rte_flow_item pattern[DP_TUNN_OPS_OFFLOAD_MAX_PATTERN];
	int pattern_cnt = 0;
	struct rte_flow_action action[DP_TUNN_OPS_OFFLOAD_MAX_ACTION];
	int action_cnt = 0;
	const struct rte_flow_action *age_action;

	memset(pattern, 0, sizeof(pattern));
	memset(action, 0, sizeof(action));

	// create flow match patterns -- eth
	struct rte_flow_item_eth eth_spec;
	struct rte_flow_item_eth eth_mask;

	pattern_cnt = insert_ethernet_match_pattern(pattern, pattern_cnt,
												&eth_spec, &eth_mask,
												NULL, 0, NULL, 0,
												htons(df->l3_type));

	// create flow match patterns -- inner packet, ipv6 or ipv4
	struct rte_flow_item_ipv6 ol_ipv6_spec;
	struct rte_flow_item_ipv6 ol_ipv6_mask;
	struct rte_flow_item_ipv4 ol_ipv4_spec;
	struct rte_flow_item_ipv4 ol_ipv4_mask;
	rte_be32_t actual_ol_ipv4_src_addr;
	rte_be32_t actual_ol_ipv4_dst_addr;

	if (df->l3_type == RTE_ETHER_TYPE_IPV6) {
		pattern_cnt = insert_ipv6_match_pattern(pattern, pattern_cnt,
												&ol_ipv6_spec, &ol_ipv6_mask,
												NULL, 0,
												df->dst.dst_addr6, sizeof(ol_ipv6_spec.hdr.dst_addr),
												df->l4_type);
	} else {
		// if this flow is the returned vip-natted flow, inner ipv4 addr shall be the VIP (NAT addr)
		if (df->flags.nat == DP_NAT_CHG_DST_IP)
			actual_ol_ipv4_dst_addr = df->nat_addr;
		else
			actual_ol_ipv4_dst_addr = df->dst.dst_addr;

		actual_ol_ipv4_src_addr = df->src.src_addr;

		pattern_cnt = insert_ipv4_match_pattern(pattern, pattern_cnt,
												&ol_ipv4_spec, &ol_ipv4_mask,
												&actual_ol_ipv4_src_addr, sizeof(actual_ol_ipv4_src_addr),
												&actual_ol_ipv4_dst_addr, sizeof(actual_ol_ipv4_dst_addr),
												df->l4_type);
	}

	// create flow match patterns -- inner packet, tcp, udp or icmp/icmpv6
	struct rte_flow_item_tcp tcp_spec;
	struct rte_flow_item_tcp tcp_mask;
	struct rte_flow_item_udp udp_spec;
	struct rte_flow_item_udp udp_mask;
	struct rte_flow_item_icmp icmp_spec;
	struct rte_flow_item_icmp icmp_mask;
	struct rte_flow_item_icmp6 icmp6_spec;
	struct rte_flow_item_icmp6 icmp6_mask;

	if (df->l4_type == DP_IP_PROTO_TCP) {
		pattern_cnt = insert_tcp_match_pattern(pattern, pattern_cnt,
											   &tcp_spec, &tcp_mask,
											   df->l4_info.trans_port.src_port, df->l4_info.trans_port.dst_port,
											   DP_RTE_TCP_CNTL_FLAGS);
	} else if (df->l4_type == DP_IP_PROTO_UDP) {
		pattern_cnt = insert_udp_match_pattern(pattern, pattern_cnt,
											   &udp_spec, &udp_mask,
											   df->l4_info.trans_port.src_port, df->l4_info.trans_port.dst_port);
	} else if (df->l4_type == DP_IP_PROTO_ICMP) {
		pattern_cnt = insert_icmp_match_pattern(pattern, pattern_cnt,
												&icmp_spec, &icmp_mask,
												df->l4_info.icmp_field.icmp_type);
	} else if (df->l4_type == DP_IP_PROTO_ICMPV6) {
		pattern_cnt = insert_icmpv6_match_pattern(pattern, pattern_cnt,
												  &icmp6_spec, &icmp6_mask,
												  df->l4_info.icmp_field.icmp_type);
	}

	// create flow match patterns -- end
	pattern_cnt = insert_end_match_pattern(pattern, pattern_cnt);

	// create flow action -- set dst mac
	struct rte_flow_action_set_mac set_dst_mac;

	action_cnt = create_dst_mac_set_action(action, action_cnt,
										   &set_dst_mac, dp_get_neigh_mac(df->nxt_hop));

	// create flow action -- set src mac
	struct rte_flow_action_set_mac set_src_mac;

	action_cnt = create_src_mac_set_action(action, action_cnt,
										   &set_src_mac, dp_get_mac(df->nxt_hop));

	// create flow action -- replace ipv4 address in overlay if vip nat is enabled
	struct rte_flow_action_set_ipv4 set_ipv4;

	if (df->flags.nat == DP_NAT_CHG_DST_IP) {
		action_cnt = create_ipv4_set_action(action, action_cnt,
										    &set_ipv4, df->dst.dst_addr, DP_IS_DST);
	} else if (df->flags.nat == DP_NAT_CHG_SRC_IP) {
		// there should be more strict condition to only apply to VIP nat pkt
		action_cnt = create_ipv4_set_action(action, action_cnt,
										    &set_ipv4, df->nat_addr, DP_IS_SRC);
	}

	// create flow action -- age
	struct rte_flow_action_age flow_age;
	struct flow_age_ctx *agectx = rte_zmalloc("age_ctx", sizeof(struct flow_age_ctx), RTE_CACHE_LINE_SIZE);

	if (!agectx) {
		DPS_LOG_ERR("Cannot allocate local flow age_ctx");
		return DP_ERROR;
	}
	age_action = &action[action_cnt];
	action_cnt = create_flow_age_action(action, action_cnt,
										&flow_age, df->conntrack->timeout_value, agectx);

	// create flow action -- send to port
	struct rte_flow_action_port_id send_to_port;

	action_cnt = create_send_to_port_action(action, action_cnt,
											&send_to_port, df->nxt_hop);
	// create flow action -- end
	action_cnt = create_end_action(action, action_cnt);

	// TODO: this attribute has not been tested with DPDK 22.11, so maybe this attribute should be ifdef'd too
	if (DP_FAILED(dp_install_rte_flow_with_indirect(m->port, &dp_flow_attr_transfer,
													pattern, action,
													age_action, df, agectx))
	) {
		free_allocated_agectx(agectx);
		DPS_LOG_ERR("Failed to install local flow rule", DP_LOG_PORTID(m->port));
	}
	DPS_LOG_DEBUG("Installed local flow rule", DP_LOG_PORTID(m->port));

	return DP_OK;
}

static __rte_always_inline int dp_offload_handle_in_network_traffic(struct rte_mbuf *m, struct dp_flow *df)
{
	struct rte_flow_item pattern[DP_TUNN_OPS_OFFLOAD_MAX_PATTERN];
	int pattern_cnt = 0;
	struct rte_flow_action action[DP_TUNN_OPS_OFFLOAD_MAX_ACTION];
	int action_cnt = 0;

	memset(pattern, 0, sizeof(pattern));
	memset(action, 0, sizeof(action));

	// in network traffic has to be set via the other pf port via hairpin
	df->nxt_hop = m->port == dp_port_get_pf0_id() ? dp_port_get_pf1_id() : dp_port_get_pf0_id();

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

	// trick: ul_src_addr6 is actually the original dst ipv6 of bouncing pkt
	pattern_cnt = insert_ipv6_match_pattern(pattern, pattern_cnt,
											&ipv6_spec, &ipv6_mask,
											NULL, 0,
											df->tun_info.ul_src_addr6, sizeof(df->tun_info.ul_src_addr6),
											df->tun_info.proto_id);

	// pattern_cnt_before_inner_hdr = pattern_cnt;

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
												NULL, 0,
												&df->dst.dst_addr, sizeof(df->dst.dst_addr),
												df->l4_type);
	}

	// create flow match patterns -- inner packet, tcp, udp or icmp/icmpv6
	struct rte_flow_item_tcp tcp_spec;
	struct rte_flow_item_tcp tcp_mask;
	struct rte_flow_item_udp udp_spec;
	struct rte_flow_item_udp udp_mask;
	struct rte_flow_item_icmp icmp_spec;
	struct rte_flow_item_icmp icmp_mask;
	struct rte_flow_item_icmp6 icmp6_spec;
	struct rte_flow_item_icmp6 icmp6_mask;

	if (df->l4_type == DP_IP_PROTO_TCP) {
		pattern_cnt = insert_tcp_match_pattern(pattern, pattern_cnt,
											   &tcp_spec, &tcp_mask,
											   df->l4_info.trans_port.src_port, df->l4_info.trans_port.dst_port, 0);
	} else if (df->l4_type == DP_IP_PROTO_UDP) {
		pattern_cnt = insert_udp_match_pattern(pattern, pattern_cnt,
											   &udp_spec, &udp_mask,
											   df->l4_info.trans_port.src_port, df->l4_info.trans_port.dst_port);
	} else if (df->l4_type == DP_IP_PROTO_ICMP) {
		pattern_cnt = insert_icmp_match_pattern(pattern, pattern_cnt,
												&icmp_spec, &icmp_mask,
												df->l4_info.icmp_field.icmp_type);
	} else if (df->l4_type == DP_IP_PROTO_ICMPV6) {
		pattern_cnt = insert_icmpv6_match_pattern(pattern, pattern_cnt,
												  &icmp6_spec, &icmp6_mask,
												  df->l4_info.icmp_field.icmp_type);
	}

	// create flow match patterns -- end
	pattern_cnt = insert_end_match_pattern(pattern, pattern_cnt);

	// create flow action -- set src mac
	struct rte_flow_action_set_mac set_src_mac_action;

	action_cnt = create_src_mac_set_action(action, action_cnt, &set_src_mac_action, dp_get_mac(df->nxt_hop));

	// create flow action -- set dst mac
	struct rte_flow_action_set_mac set_dst_mac_action;

	action_cnt = create_dst_mac_set_action(action, action_cnt, &set_dst_mac_action, dp_get_neigh_mac(df->nxt_hop));

	// create flow action -- set ipv6
	struct rte_flow_action_set_ipv6 set_ipv6;

	action_cnt = create_ipv6_set_action(action, action_cnt,
									&set_ipv6, df->tun_info.ul_dst_addr6, DP_IS_DST);

	// create flow action -- age
	struct rte_flow_action_age flow_age;
	struct flow_age_ctx *agectx = rte_zmalloc("age_ctx", sizeof(struct flow_age_ctx), RTE_CACHE_LINE_SIZE);

	if (!agectx) {
		DPS_LOG_ERR("Cannot allocate in-network flow age_ctx");
		return DP_ERROR;
	}

	action_cnt = create_flow_age_action(action, action_cnt,
											&flow_age, 30, agectx);

	// create flow action -- queue
	// move this packet to the right hairpin rx queue of pf, so as to be moved to vf
	struct rte_flow_action_queue queue_action;
	// it is the 1st hairpin rx queue of pf, which is paired with another hairpin tx queue of pf
	uint16_t hairpin_rx_queue_id = DP_NR_STD_RX_QUEUES;

	action_cnt = create_redirect_queue_action(action, action_cnt, &queue_action, hairpin_rx_queue_id);

	// create flow action -- end
	action_cnt = create_end_action(action, action_cnt);

	// bouncing back rule's expiration is taken care of by the rte flow rule expiration mechanism;
	// no need to perform query to perform checking on expiration status, thus indirect action is not needed
	if (DP_FAILED(dp_install_rte_flow_with_age(m->port, &dp_flow_attr_ingress, pattern, action, df->conntrack, agectx))) {
		free_allocated_agectx(agectx);
		DPS_LOG_ERR("Failed to install in-network decap flow rule on PF", DP_LOG_PORTID(m->port));
		return DP_ERROR;
	}
	DPS_LOG_DEBUG("Installed in-network decap flow rule on PF", DP_LOG_PORTID(m->port));

	return DP_OK;
}

int dp_offload_handler(struct rte_mbuf *m, struct dp_flow *df)
{

	if (df->flags.flow_type == DP_FLOW_TYPE_LOCAL)
		return dp_offload_handle_local_traffic(m, df);

	if (df->flags.flow_type == DP_FLOW_TYPE_INCOMING)
		return dp_offload_handle_tunnel_decap_traffic(m, df);

	if (df->flags.flow_type == DP_FLOW_TYPE_OUTGOING) {
		if (df->conntrack->nf_info.nat_type == DP_FLOW_NAT_TYPE_NETWORK_NEIGH
				|| df->conntrack->nf_info.nat_type == DP_FLOW_LB_TYPE_FORWARD)
			return dp_offload_handle_in_network_traffic(m, df);
		else
			return dp_offload_handle_tunnel_encap_traffic(m, df);
	}

	DPS_LOG_ERR("Invalid flow type to offload", DP_LOG_VALUE(df->flags.flow_type));
	return DP_ERROR;
}
