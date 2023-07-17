#include "rte_flow/dp_rte_flow_traffic_forward.h"
#include "dp_nat.h"
#include "dp_log.h"
#include "dp_error.h"

static __rte_always_inline int dp_offload_handle_tunnel_encap_traffic(struct rte_mbuf *m, struct dp_flow *df)
{
	printf("dp_offload_handle_tunnel_encap_traffic\n");
	struct underlay_conf *u_conf = get_underlay_conf();
	bool cross_pf_port = df->nxt_hop == dp_port_get_pf0_id() ? false : true;

	struct rte_flow_attr attr;

	struct rte_flow_item pattern[DP_TUNN_OPS_OFFLOAD_MAX_PATTERN];
	int pattern_cnt = 0;
	struct rte_flow_item hairpin_pattern[DP_TUNN_OPS_OFFLOAD_MAX_PATTERN];
	int hairpin_pattern_cnt = 0;
	struct rte_flow_action action[DP_TUNN_OPS_OFFLOAD_MAX_ACTION];
	int action_cnt = 0;
	struct rte_flow_action hairpin_action[DP_TUNN_OPS_OFFLOAD_MAX_ACTION];
	int hairpin_action_cnt = 0;

	int age_action_index;
	int ret;

	memset(pattern, 0, sizeof(pattern));
	memset(hairpin_pattern, 0, sizeof(hairpin_pattern));
	memset(action, 0, sizeof(action));
	memset(hairpin_action, 0, sizeof(hairpin_action));

	uint8_t vni_in_mac_addr[RTE_ETHER_ADDR_LEN];

	memset(vni_in_mac_addr, 0, sizeof(vni_in_mac_addr));
	memcpy(vni_in_mac_addr, &df->tun_info.dst_vni, 4);

	// create flow match patterns -- eth, for maching vf packets
	struct rte_flow_item_eth ol_eth_spec;
	struct rte_flow_item_eth ol_eth_mask;

	if (cross_pf_port)
		hairpin_pattern_cnt = insert_ethernet_match_pattern(hairpin_pattern, hairpin_pattern_cnt,
												&ol_eth_spec, &ol_eth_mask,
												NULL, 0, NULL, 0,
												htons(df->l3_type));


	// create flow match patterns -- eth, for maching modified vf packets embedded with vni info
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
		if (cross_pf_port)
			hairpin_pattern_cnt = insert_ipv6_match_pattern(hairpin_pattern, hairpin_pattern_cnt,
													&ol_ipv6_spec, &ol_ipv6_mask,
													NULL, 0,
													df->dst.dst_addr6, sizeof(ol_ipv6_spec.hdr.dst_addr),
													df->l4_type);

		pattern_cnt = insert_ipv6_match_pattern(pattern, pattern_cnt,
												&ol_ipv6_spec, &ol_ipv6_mask,
												NULL, 0,
												df->dst.dst_addr6, sizeof(ol_ipv6_spec.hdr.dst_addr),
												df->l4_type);
	} else {
		if (cross_pf_port)
			hairpin_pattern_cnt = insert_ipv4_match_pattern(hairpin_pattern, hairpin_pattern_cnt,
													&ol_ipv4_spec, &ol_ipv4_mask,
													NULL, 0,
													&df->dst.dst_addr, sizeof(ol_ipv4_spec.hdr.dst_addr),
													df->l4_type);

		pattern_cnt = insert_ipv4_match_pattern(pattern, pattern_cnt,
												&ol_ipv4_spec, &ol_ipv4_mask,
												NULL, 0,
												&df->dst.dst_addr, sizeof(ol_ipv4_spec.hdr.dst_addr),
												df->l4_type);
	}

	// create flow match patterns -- inner packet, tcp, udp or icmp/icmpv6
	struct rte_flow_item_tcp tcp_spec;
	struct rte_flow_item_tcp tcp_mask;

	if (df->l4_type == DP_IP_PROTO_TCP) {
		if (cross_pf_port)
			hairpin_pattern_cnt = insert_tcp_match_pattern(hairpin_pattern, hairpin_pattern_cnt,
													&tcp_spec, &tcp_mask,
													df->l4_info.trans_port.src_port, df->l4_info.trans_port.dst_port,
													DP_RTE_TCP_CNTL_FLAGS);
		pattern_cnt = insert_tcp_match_pattern(pattern, pattern_cnt,
											   &tcp_spec, &tcp_mask,
											   df->l4_info.trans_port.src_port, df->l4_info.trans_port.dst_port,
											   DP_RTE_TCP_CNTL_FLAGS);
	}

	struct rte_flow_item_udp udp_spec;
	struct rte_flow_item_udp udp_mask;

	if (df->l4_type == DP_IP_PROTO_UDP) {
		if (cross_pf_port)
			hairpin_pattern_cnt = insert_udp_match_pattern(hairpin_pattern, hairpin_pattern_cnt,
												&udp_spec, &udp_mask,
												df->l4_info.trans_port.src_port, df->l4_info.trans_port.dst_port);
		pattern_cnt = insert_udp_match_pattern(pattern, pattern_cnt,
											   &udp_spec, &udp_mask,
											   df->l4_info.trans_port.src_port, df->l4_info.trans_port.dst_port);
	}

	struct rte_flow_item_icmp icmp_spec;
	struct rte_flow_item_icmp icmp_mask;

	if (df->l4_type == DP_IP_PROTO_ICMP) {
		if (cross_pf_port)
			hairpin_pattern_cnt = insert_icmp_match_pattern(hairpin_pattern, hairpin_pattern_cnt,
													&icmp_spec, &icmp_mask,
													df->l4_info.icmp_field.icmp_type);
		pattern_cnt = insert_icmp_match_pattern(pattern, pattern_cnt,
												&icmp_spec, &icmp_mask,
												df->l4_info.icmp_field.icmp_type);
	}

	struct rte_flow_item_icmp6 icmp6_spec;
	struct rte_flow_item_icmp6 icmp6_mask;

	if (df->l4_type == DP_IP_PROTO_ICMPV6) {
		if (cross_pf_port)
			hairpin_pattern_cnt = insert_icmpv6_match_pattern(hairpin_pattern, hairpin_pattern_cnt,
													&icmp6_spec, &icmp6_mask,
													df->l4_info.icmp_field.icmp_type);
		pattern_cnt = insert_icmpv6_match_pattern(pattern, pattern_cnt,
												  &icmp6_spec, &icmp6_mask,
												  df->l4_info.icmp_field.icmp_type);
	}

	// create flow match patterns -- end
	if (cross_pf_port)
		hairpin_pattern_cnt = insert_end_match_pattern(hairpin_pattern, hairpin_pattern_cnt);

	pattern_cnt = insert_end_match_pattern(pattern, pattern_cnt);


	/*Firstly install a flow rule to modify mac addr to embed vni info and move packet to hairpin rxq*/
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

		if (!hairpin_agectx)
			return 0;
		hairpin_action_cnt = create_flow_age_action(hairpin_action, hairpin_action_cnt,
										&flow_age, df->conntrack->timeout_value, hairpin_agectx);
		age_action_index = hairpin_action_cnt - 1;
		// create flow action -- end
		hairpin_action_cnt = create_end_action(hairpin_action, hairpin_action_cnt);

		// validate and install rte flow
		create_rte_flow_rule_attr(&attr, 0, 0, 1, 0, 0);
		struct rte_flow *hairpin_flow = NULL;

		ret = dp_create_age_indirect_action(&attr, m->port, df, &hairpin_action[age_action_index], hairpin_agectx);
		if (DP_FAILED(ret)) {
			free_allocated_agectx(hairpin_agectx);
			return 0;
		}

		hairpin_flow = validate_and_install_rte_flow(m->port, &attr, hairpin_pattern, hairpin_action);
		if (!hairpin_flow) {
			free_allocated_agectx(hairpin_agectx);
			DPS_LOG_ERR("Failed to install hairpin queue flow rule on vf", DP_LOG_PORTID(m->port));
			return 0;
		}
		config_allocated_agectx(hairpin_agectx, m->port, df, hairpin_flow);
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
	struct flow_age_ctx *agectx = rte_zmalloc("age_ctx", sizeof(struct flow_age_ctx), RTE_CACHE_LINE_SIZE);
	struct rte_flow_action_age flow_age;

	if (!agectx)
		return 0;
	action_cnt = create_flow_age_action(action, action_cnt,
										&flow_age, df->conntrack->timeout_value, agectx);
	age_action_index = action_cnt - 1;

	// create flow action -- send to port
	struct rte_flow_action_port_id send_to_port;

	if (!cross_pf_port)
		action_cnt = create_send_to_port_action(action, action_cnt,
												&send_to_port, df->nxt_hop);


	// create flow action -- end
	action_cnt = create_end_action(action, action_cnt);

	// validate and install rte flow
	struct rte_flow *flow = NULL;

	if (cross_pf_port)
		create_rte_flow_rule_attr(&attr, 0, 0, 0, 1, 0);
	else {
		#ifdef ENABLE_DPDK_22_11
			create_rte_flow_rule_attr(&attr, 0, 0, 0, 0, 1);
		#else
			create_rte_flow_rule_attr(&attr, 0, 0, 1, 0, 1);
		#endif
	}


	uint16_t t_port_id = cross_pf_port ? dp_port_get_pf1_id() : m->port;

	ret = dp_create_age_indirect_action(&attr, t_port_id, df, &action[age_action_index], agectx);
	if (DP_FAILED(ret)) {
		free_allocated_agectx(agectx);
		return 0;
	}

	flow = validate_and_install_rte_flow(t_port_id, &attr, pattern, action);
	if (!flow) {
		free_allocated_agectx(agectx);
		DPS_LOG_ERR("Failed to install encap rule on PF", DP_LOG_PORTID(t_port_id));
		return 0;
	}

	// config the content of agectx
	config_allocated_agectx(agectx, t_port_id, df, flow);
	return 1;
}

static __rte_always_inline int dp_offload_handle_tunnel_decap_traffic(struct rte_mbuf *m, struct dp_flow *df)
{
	bool cross_pf_port = m->port == dp_port_get_pf0_id() ? false : true;

	printf("dp_offload_handle_tunnel_decap_traffic\n");

	struct rte_flow_attr attr;
	int hairpin_pattern_cnt = 0;
	struct rte_flow_item pattern[DP_TUNN_OPS_OFFLOAD_MAX_PATTERN];
	int pattern_cnt = 0;
	struct rte_flow_item hairpin_pattern[DP_TUNN_OPS_OFFLOAD_MAX_PATTERN];
	struct rte_flow_action action[DP_TUNN_OPS_OFFLOAD_MAX_ACTION];
	int action_cnt = 0;
	int age_action_index;
	int ret = 0;

	#if !defined(ENABLE_DPDK_22_11)
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
	uint32_t actual_ol_ipv4_addr;

	if (df->l3_type == RTE_ETHER_TYPE_IPV6) {
		pattern_cnt = insert_ipv6_match_pattern(pattern, pattern_cnt,
												&ol_ipv6_spec, &ol_ipv6_mask,
												NULL, 0,
												df->dst.dst_addr6, sizeof(ol_ipv6_spec.hdr.dst_addr),
												df->l4_type);
		if (cross_pf_port)
			hairpin_pattern_cnt = insert_ipv6_match_pattern(hairpin_pattern, hairpin_pattern_cnt,
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
		if (cross_pf_port)
			hairpin_pattern_cnt = insert_ipv4_match_pattern(hairpin_pattern, hairpin_pattern_cnt,
													&ol_ipv4_spec, &ol_ipv4_mask,
													NULL, 0,
													&actual_ol_ipv4_addr, sizeof(actual_ol_ipv4_addr),
													df->l4_type);
	}

	// create flow match patterns -- inner packet, tcp, udp or icmp/icmpv6
	struct rte_flow_item_tcp tcp_spec;
	struct rte_flow_item_tcp tcp_mask;

	if (df->l4_type == DP_IP_PROTO_TCP) {
		pattern_cnt = insert_tcp_match_pattern(pattern, pattern_cnt,
											   &tcp_spec, &tcp_mask,
											   df->l4_info.trans_port.src_port, df->l4_info.trans_port.dst_port,
											   DP_RTE_TCP_CNTL_FLAGS);
		if (cross_pf_port)
			hairpin_pattern_cnt = insert_tcp_match_pattern(hairpin_pattern, hairpin_pattern_cnt,
												&tcp_spec, &tcp_mask,
												df->l4_info.trans_port.src_port, df->l4_info.trans_port.dst_port,
												DP_RTE_TCP_CNTL_FLAGS);

	}

	struct rte_flow_item_udp udp_spec;
	struct rte_flow_item_udp udp_mask;

	if (df->l4_type == DP_IP_PROTO_UDP) {
		pattern_cnt = insert_udp_match_pattern(pattern, pattern_cnt,
											   &udp_spec, &udp_mask,
											   df->l4_info.trans_port.src_port, df->l4_info.trans_port.dst_port);
		if (cross_pf_port)
			hairpin_pattern_cnt = insert_udp_match_pattern(hairpin_pattern, hairpin_pattern_cnt,
												&udp_spec, &udp_mask,
												df->l4_info.trans_port.src_port, df->l4_info.trans_port.dst_port);
	}

	struct rte_flow_item_icmp icmp_spec;
	struct rte_flow_item_icmp icmp_mask;

	if (df->l4_type == DP_IP_PROTO_ICMP) {
		pattern_cnt = insert_icmp_match_pattern(pattern, pattern_cnt,
												&icmp_spec, &icmp_mask,
												df->l4_info.icmp_field.icmp_type);
		if (cross_pf_port)
			hairpin_pattern_cnt = insert_icmp_match_pattern(hairpin_pattern, hairpin_pattern_cnt,
													&icmp_spec, &icmp_mask,
													df->l4_info.icmp_field.icmp_type);
	}

	struct rte_flow_item_icmp6 icmp6_spec;
	struct rte_flow_item_icmp6 icmp6_mask;

	if (df->l4_type == DP_IP_PROTO_ICMPV6) {
		pattern_cnt = insert_icmpv6_match_pattern(pattern, pattern_cnt,
												  &icmp6_spec, &icmp6_mask,
												  df->l4_info.icmp_field.icmp_type);
		if (cross_pf_port)
			hairpin_pattern_cnt = insert_icmpv6_match_pattern(hairpin_pattern, hairpin_pattern_cnt,
													&icmp6_spec, &icmp6_mask,
													df->l4_info.icmp_field.icmp_type);
	}

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
	struct flow_age_ctx *agectx = rte_zmalloc("age_ctx", sizeof(struct flow_age_ctx), RTE_CACHE_LINE_SIZE);
	struct rte_flow_action_age flow_age;

	if (!agectx)
		return 0;

	action_cnt = create_flow_age_action(action, action_cnt,
											&flow_age, df->conntrack->timeout_value, agectx);
	age_action_index = action_cnt - 1;

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
	if (cross_pf_port) {
		create_rte_flow_rule_attr(&attr, 0, 0, 1, 0, 0);
		struct rte_flow *hairpin_flow = NULL;

		hairpin_flow = validate_and_install_rte_flow(m->port, &attr, pattern, action);
		if (!hairpin_flow) {
			free_allocated_agectx(agectx);
			return 0;
		}
		// config the content of agectx
		config_allocated_agectx(agectx, m->port, df, hairpin_flow);
	} else {
		#ifdef ENABLE_DPDK_22_11
			create_rte_flow_rule_attr(&attr, 0, 0, 0, 0, 1);
		#else
			create_rte_flow_rule_attr(&attr, 0, 0, 1, 0, 1);
		#endif

		struct rte_flow *flow = NULL;

		flow = validate_and_install_rte_flow(m->port, &attr, pattern, action);
		if (!flow) {
			free_allocated_agectx(agectx);
			DPS_LOG_ERR("Failed to install normal decap flow rule on PF", DP_LOG_PORTID(m->port));
			return 0;
		}
		// config the content of agectx
		config_allocated_agectx(agectx, m->port, df, flow);
	}


	ret = dp_create_age_indirect_action(&attr, m->port, df, &action[age_action_index], agectx);
	if (DP_FAILED(ret)) {
		free_allocated_agectx(agectx);
		return 0;
	}

	#if !defined(ENABLE_DPDK_22_11)
	// create flow action -- set dst mac
	/* This redundant action is needed to make hairpin work*/
	struct rte_flow_action_set_mac set_dst_mac;
	struct rte_flow_action_age hairpin_flow_age;

	if (cross_pf_port) {
		hairpin_action_cnt = create_dst_mac_set_action(hairpin_action, hairpin_action_cnt,
											&set_dst_mac, &new_eth_hdr->dst_addr);
		// create flow action -- age
		struct flow_age_ctx *hairpin_agectx = rte_zmalloc("age_ctx", sizeof(struct flow_age_ctx), RTE_CACHE_LINE_SIZE);

		if (!hairpin_agectx)
			return 0;
		hairpin_action_cnt = create_flow_age_action(hairpin_action, hairpin_action_cnt,
											&hairpin_flow_age, df->conntrack->timeout_value, hairpin_agectx);

		age_action_index = hairpin_action_cnt - 1;
		// create flow action -- end
		hairpin_action_cnt = create_end_action(hairpin_action, hairpin_action_cnt);
		// validate and install rte flow
		struct rte_flow *hairpin_flow_P2 = NULL;

		create_rte_flow_rule_attr(&attr, 0, 0, 0, 1, 0);


		ret = dp_create_age_indirect_action(&attr, (uint16_t)df->nxt_hop, df, &hairpin_action[age_action_index], hairpin_agectx);
		if (DP_FAILED(ret)) {
			free_allocated_agectx(hairpin_agectx);
			return 0;
		}

		hairpin_flow_P2 = validate_and_install_rte_flow((uint16_t)df->nxt_hop, &attr, pattern, hairpin_action);
		if (!hairpin_flow_P2) {
			free_allocated_agectx(hairpin_agectx);
			DPS_LOG_ERR("Failed to install hairpin queue flow rule on VF", DP_LOG_PORTID(df->nxt_hop));
			return 0;
		}
		config_allocated_agectx(hairpin_agectx, df->nxt_hop, df, hairpin_flow_P2);
	}
	#endif

	return 1;
}

static __rte_always_inline int dp_offload_handle_local_traffic(struct rte_mbuf *m, struct dp_flow *df)
{

	printf("dp_offload_handle_local_traffic\n");
	struct rte_flow_attr attr;

	create_rte_flow_rule_attr(&attr, 0, 0, 1, 0, 1);

	struct rte_flow_item pattern[DP_TUNN_OPS_OFFLOAD_MAX_PATTERN];
	int pattern_cnt = 0;
	struct rte_flow_action action[DP_TUNN_OPS_OFFLOAD_MAX_ACTION];
	int action_cnt = 0;
	int ret = 0;

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
	uint32_t actual_ol_ipv4_src_addr = 0;
	uint32_t actual_ol_ipv4_dst_addr = 0;

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

	if (df->l4_type == DP_IP_PROTO_TCP) {
		pattern_cnt = insert_tcp_match_pattern(pattern, pattern_cnt,
											   &tcp_spec, &tcp_mask,
											   df->l4_info.trans_port.src_port, df->l4_info.trans_port.dst_port,
											   DP_RTE_TCP_CNTL_FLAGS);
	}

	struct rte_flow_item_udp udp_spec;
	struct rte_flow_item_udp udp_mask;

	if (df->l4_type == DP_IP_PROTO_UDP) {
		pattern_cnt = insert_udp_match_pattern(pattern, pattern_cnt,
											   &udp_spec, &udp_mask,
											   df->l4_info.trans_port.src_port, df->l4_info.trans_port.dst_port);
	}

	struct rte_flow_item_icmp icmp_spec;
	struct rte_flow_item_icmp icmp_mask;

	if (df->l4_type == DP_IP_PROTO_ICMP) {
		pattern_cnt = insert_icmp_match_pattern(pattern, pattern_cnt,
												&icmp_spec, &icmp_mask,
												df->l4_info.icmp_field.icmp_type);
	}

	struct rte_flow_item_icmp6 icmp6_spec;
	struct rte_flow_item_icmp6 icmp6_mask;

	if (df->l4_type == DP_IP_PROTO_ICMPV6) {
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
	if (df->flags.nat == DP_NAT_CHG_DST_IP)
		action_cnt = create_ipv4_set_action(action, action_cnt,
										    &set_ipv4, df->dst.dst_addr, DP_IS_DST);

	// there should be more strict condition to only apply to VIP nat pkt
	if (df->flags.nat == DP_NAT_CHG_SRC_IP)
		action_cnt = create_ipv4_set_action(action, action_cnt,
										    &set_ipv4, df->nat_addr, DP_IS_SRC);

	// create flow action -- age
	struct flow_age_ctx *agectx = rte_zmalloc("age_ctx", sizeof(struct flow_age_ctx), RTE_CACHE_LINE_SIZE);
	struct rte_flow_action_age flow_age;

	if (!agectx)
		return 0;

	action_cnt = create_flow_age_action(action, action_cnt,
										&flow_age, df->conntrack->timeout_value, agectx);

	ret = dp_create_age_indirect_action(&attr, m->port, df, &action[action_cnt-1], agectx);
	if (DP_FAILED(ret)) {
		free_allocated_agectx(agectx);
		return 0;
	}

	// create flow action -- send to port
	struct rte_flow_action_port_id send_to_port;

	action_cnt = create_send_to_port_action(action, action_cnt,
											&send_to_port, df->nxt_hop);
	// create flow action -- end
	action_cnt = create_end_action(action, action_cnt);

	// validate and install rte flow
	struct rte_flow *flow = NULL;

	flow = validate_and_install_rte_flow(m->port, &attr, pattern, action);
	if (!flow) {
		free_allocated_agectx(agectx);
		DPS_LOG_ERR("Failed to validate and install rte flow rules");
		return 0;
	}

	// config the content of agectx
	config_allocated_agectx(agectx, m->port, df, flow);

	return 1;
}

static __rte_always_inline int dp_offload_handle_in_network_traffic(struct rte_mbuf *m, struct dp_flow *df)
{
	struct rte_flow_attr attr;
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
	// uint32_t actual_ol_ipv4_addr;

	if (df->l3_type == RTE_ETHER_TYPE_IPV6)
		pattern_cnt = insert_ipv6_match_pattern(pattern, pattern_cnt,
												&ol_ipv6_spec, &ol_ipv6_mask,
												NULL, 0,
												df->dst.dst_addr6, sizeof(ol_ipv6_spec.hdr.dst_addr),
												df->l4_type);
	else
		pattern_cnt = insert_ipv4_match_pattern(pattern, pattern_cnt,
												&ol_ipv4_spec, &ol_ipv4_mask,
												NULL, 0,
												&df->dst.dst_addr, sizeof(df->dst.dst_addr),
												df->l4_type);

	// create flow match patterns -- inner packet, tcp, udp or icmp/icmpv6
	struct rte_flow_item_tcp tcp_spec;
	struct rte_flow_item_tcp tcp_mask;

	if (df->l4_type == DP_IP_PROTO_TCP)
		pattern_cnt = insert_tcp_match_pattern(pattern, pattern_cnt,
											   &tcp_spec, &tcp_mask,
											   df->l4_info.trans_port.src_port, df->l4_info.trans_port.dst_port, 0);

	struct rte_flow_item_udp udp_spec;
	struct rte_flow_item_udp udp_mask;

	if (df->l4_type == DP_IP_PROTO_UDP)
		pattern_cnt = insert_udp_match_pattern(pattern, pattern_cnt,
											   &udp_spec, &udp_mask,
											   df->l4_info.trans_port.src_port, df->l4_info.trans_port.dst_port);

	struct rte_flow_item_icmp icmp_spec;
	struct rte_flow_item_icmp icmp_mask;

	if (df->l4_type == DP_IP_PROTO_ICMP)
		pattern_cnt = insert_icmp_match_pattern(pattern, pattern_cnt,
												&icmp_spec, &icmp_mask,
												df->l4_info.icmp_field.icmp_type);

	struct rte_flow_item_icmp6 icmp6_spec;
	struct rte_flow_item_icmp6 icmp6_mask;

	if (df->l4_type == DP_IP_PROTO_ICMPV6)
		pattern_cnt = insert_icmpv6_match_pattern(pattern, pattern_cnt,
												  &icmp6_spec, &icmp6_mask,
												  df->l4_info.icmp_field.icmp_type);

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
	struct flow_age_ctx *agectx = rte_zmalloc("age_ctx", sizeof(struct flow_age_ctx), RTE_CACHE_LINE_SIZE);
	struct rte_flow_action_age flow_age;

	if (!agectx)
		return 0;

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

	// validate and install rte flow
	struct rte_flow *flow = NULL;

	create_rte_flow_rule_attr(&attr, 0, 0, 1, 0, 0);

	flow = validate_and_install_rte_flow(m->port, &attr, pattern, action);
	if (!flow) {
		free_allocated_agectx(agectx);
		DPS_LOG_ERR("Failed to install in-network decap flow rule on pf", DP_LOG_PORTID(m->port));
		return 0;
	}
	// config the content of agectx
	config_allocated_agectx(agectx, m->port, df, flow);

	return 1;
}

// TODO maybe pass node for better logging
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

	return 0;
}
