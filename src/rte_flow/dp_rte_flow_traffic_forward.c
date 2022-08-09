#include "rte_flow/dp_rte_flow_traffic_forward.h"
#include "dp_nat.h"

static __rte_always_inline int dp_handle_tunnel_encap_offload(struct rte_mbuf *m, struct dp_flow *df)
{

	struct underlay_conf *u_conf = get_underlay_conf();

	struct rte_flow_attr attr;
	create_rte_flow_rule_attr(&attr, 0, 0, 1, 0, 1);

	struct rte_flow_item pattern[DP_TUNN_OPS_OFFLOAD_MAX_PATTERN];
	int pattern_cnt = 0;
	struct rte_flow_action action[DP_TUNN_OPS_OFFLOAD_MAX_ACTION];
	int action_cnt = 0;
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

	if (df->l3_type == RTE_ETHER_TYPE_IPV6)
	{
		pattern_cnt = insert_ipv6_match_pattern(pattern, pattern_cnt,
												&ol_ipv6_spec, &ol_ipv6_mask,
												NULL, 0,
												df->dst.dst_addr6, sizeof(ol_ipv6_spec.hdr.dst_addr),
												df->l4_type);
	}
	else
	{
		pattern_cnt = insert_ipv4_match_pattern(pattern, pattern_cnt,
												&ol_ipv4_spec, &ol_ipv4_mask,
												df, DP_IS_DST);
	}

	// create flow match patterns -- inner packet, tcp, udp or icmp/icmpv6
	struct rte_flow_item_tcp tcp_spec;
	struct rte_flow_item_tcp tcp_mask;
	if (df->l4_type == DP_IP_PROTO_TCP)
	{
		pattern_cnt = insert_tcp_match_pattern(pattern, pattern_cnt,
											   &tcp_spec, &tcp_mask,
											   df->src_port, df->dst_port);
	}

	struct rte_flow_item_udp udp_spec;
	struct rte_flow_item_udp udp_mask;
	if (df->l4_type == DP_IP_PROTO_UDP)
	{
		pattern_cnt = insert_udp_match_pattern(pattern, pattern_cnt,
											   &udp_spec, &udp_mask,
											   df->src_port, df->dst_port);
	}

	struct rte_flow_item_icmp icmp_spec;
	struct rte_flow_item_icmp icmp_mask;
	if (df->l4_type == DP_IP_PROTO_ICMP)
	{
		pattern_cnt = insert_icmp_match_pattern(pattern, pattern_cnt,
												&icmp_spec, &icmp_mask,
												df->icmp_type);
	}

	struct rte_flow_item_icmp6 icmp6_spec;
	struct rte_flow_item_icmp6 icmp6_mask;
	if (df->l4_type == DP_IP_PROTO_ICMPV6)
	{
		pattern_cnt = insert_icmpv6_match_pattern(pattern, pattern_cnt,
												  &icmp6_spec, &icmp6_mask,
												  df->icmp_type);
	}

	// create flow match patterns -- end
	pattern_cnt = insert_end_match_pattern(pattern, pattern_cnt);

	// create flow action -- raw decap
	struct rte_flow_action_raw_decap raw_decap;
	action_cnt = create_raw_decap_action(action, action_cnt,
										 &raw_decap, NULL, sizeof(struct rte_ether_hdr));

	// create flow action -- raw encap
	uint8_t ipip_encap_hdr[DP_TUNN_IPIP_ENCAP_SIZE];
	memset(ipip_encap_hdr, 0, DP_TUNN_IPIP_ENCAP_SIZE);

	uint8_t geneve_encap_hdr[DP_TUNN_GENEVE_ENCAP_SIZE];
	memset(geneve_encap_hdr, 0, DP_TUNN_GENEVE_ENCAP_SIZE);

	uint8_t *encap_hdr = NULL;
	size_t raw_encap_size = 0;
	if (get_overlay_type() == DP_FLOW_OVERLAY_TYPE_GENEVE)
	{
		encap_hdr = geneve_encap_hdr;
		raw_encap_size = DP_TUNN_GENEVE_ENCAP_SIZE;
	}
	else
	{
		encap_hdr = ipip_encap_hdr;
		raw_encap_size = DP_TUNN_IPIP_ENCAP_SIZE;
	}

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

	if (get_overlay_type() == DP_FLOW_OVERLAY_TYPE_GENEVE)
	{
		struct rte_udp_hdr *new_udp_hdr = (struct rte_udp_hdr *)(new_ipv6_hdr + 1);
		new_udp_hdr->src_port = df->tun_info.src_port;
		new_udp_hdr->dst_port = df->tun_info.dst_port;

		struct rte_flow_item_geneve *new_geneve_hdr = (struct rte_flow_item_geneve *)(new_udp_hdr + 1);
		rte_memcpy(new_geneve_hdr->vni, &df->tun_info.dst_vni, sizeof(new_geneve_hdr->vni));
		new_geneve_hdr->ver_opt_len_o_c_rsvd0 = 0;
		new_geneve_hdr->protocol = htons(df->l3_type);
	}

	action_cnt = create_raw_encap_action(action, action_cnt,
										 &raw_encap, encap_hdr, raw_encap_size);

	// create flow action -- age
	struct flow_age_ctx *agectx = rte_zmalloc("age_ctx", sizeof(struct flow_age_ctx), RTE_CACHE_LINE_SIZE);
	struct rte_flow_action_age flow_age;
	if (!agectx)
		return 0;
	action_cnt = create_flow_age_action(action, action_cnt,
										&flow_age, 60, agectx);

	// create flow action -- send to port
	struct rte_flow_action_port_id send_to_port;
	action_cnt = create_send_to_port_action(action, action_cnt,
											&send_to_port, df->nxt_hop);

	// create flow action -- end
	action_cnt = create_end_action(action, action_cnt);

	// validate and install rte flow
	struct rte_flow *flow = NULL;
	flow = validate_and_install_rte_flow(m->port, &attr, pattern, action, df);
	if (!flow)
	{
		free_allocated_agectx(agectx);
		return 0;
	}

	// config the content of agectx
	config_allocated_agectx(agectx, m->port, df, flow);
	return 1;
}

static __rte_always_inline int dp_handle_tunnel_encap_hairpin_offload(struct rte_mbuf *m, struct dp_flow *df)
{

	struct underlay_conf *u_conf = get_underlay_conf();

	struct rte_flow_attr attr;
	

	struct rte_flow_item pattern[DP_TUNN_OPS_OFFLOAD_MAX_PATTERN];
	int pattern_cnt = 0;
	struct rte_flow_item hairpin_pattern[DP_TUNN_OPS_OFFLOAD_MAX_PATTERN];
	int hairpin_pattern_cnt = 0;
	struct rte_flow_action action[DP_TUNN_OPS_OFFLOAD_MAX_ACTION];
	int action_cnt = 0;
	struct rte_flow_action hairpin_action[DP_TUNN_OPS_OFFLOAD_MAX_ACTION];
	int hairpin_action_cnt = 0;
	memset(pattern, 0, sizeof(pattern));
	memset(hairpin_pattern, 0, sizeof(hairpin_pattern));
	memset(action, 0, sizeof(action));
	memset(hairpin_action, 0, sizeof(hairpin_action));

	// create flow match pattern -- mark
	// struct rte_flow_item_mark mark_spec;
	// struct rte_flow_item_mark mark_mask;
	// pattern_cnt = insert_packet_mark_match_pattern(pattern, pattern_cnt,
	// 											&mark_spec, &mark_mask,
	// 											0x64);
	// pattern_cnt = insert_packet_mark_match_pattern(pattern, pattern_cnt,
	// 											&mark_spec, &mark_mask,
	// 											df->tun_info.dst_vni);

	// struct rte_flow_item_tag tag_spec;
	// struct rte_flow_item_tag tag_mask;
	// pattern_cnt = insert_tag_match_pattern(pattern, pattern_cnt,
	// 											&tag_spec, &tag_mask,
	// 											df->tun_info.dst_vni,0);

	// struct rte_flow_item_meta meta_spec;
	// struct rte_flow_item_meta meta_mask;
	// pattern_cnt = insert_meta_match_pattern(pattern, pattern_cnt,
	// 										&meta_spec, &meta_mask,
	// 										df->tun_info.dst_vni);
	
	uint8_t vni_in_mac_addr[RTE_ETHER_ADDR_LEN];
	memset(vni_in_mac_addr,0,sizeof(vni_in_mac_addr));
	memcpy(vni_in_mac_addr, &df->tun_info.dst_vni, 4);


	// create flow match patterns -- eth, for maching vf packets
	struct rte_flow_item_eth ol_eth_spec;
	struct rte_flow_item_eth ol_eth_mask;
	hairpin_pattern_cnt = insert_ethernet_match_pattern(hairpin_pattern, hairpin_pattern_cnt,
												&ol_eth_spec, &ol_eth_mask,
												NULL, 0, NULL, 0,
												htons(df->l3_type));
	
	
	// create flow match patterns -- eth, for maching modified vf packets embedded with vni info
	struct rte_flow_item_eth eth_spec;
	struct rte_flow_item_eth eth_mask;
	struct rte_ether_addr modified_eth_dst_addr;
	memcpy(modified_eth_dst_addr.addr_bytes, vni_in_mac_addr, sizeof(struct rte_ether_addr));
	
	pattern_cnt = insert_ethernet_match_pattern(pattern, pattern_cnt,
												&eth_spec, &eth_mask,
												NULL, 0, &modified_eth_dst_addr, sizeof(struct rte_ether_addr),
												htons(df->l3_type));

	// create flow match patterns -- inner packet, ipv6 or ipv4
	struct rte_flow_item_ipv6 ol_ipv6_spec;
	struct rte_flow_item_ipv6 ol_ipv6_mask;

	struct rte_flow_item_ipv4 ol_ipv4_spec;
	struct rte_flow_item_ipv4 ol_ipv4_mask;

	if (df->l3_type == RTE_ETHER_TYPE_IPV6)
	{
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
	}
	else
	{
		hairpin_pattern_cnt = insert_ipv4_match_pattern(hairpin_pattern, hairpin_pattern_cnt,
												&ol_ipv4_spec, &ol_ipv4_mask,
												df, DP_IS_DST);
		pattern_cnt = insert_ipv4_match_pattern(pattern, pattern_cnt,
												&ol_ipv4_spec, &ol_ipv4_mask,
												df, DP_IS_DST);
	}

	// create flow match patterns -- inner packet, tcp, udp or icmp/icmpv6
	struct rte_flow_item_tcp tcp_spec;
	struct rte_flow_item_tcp tcp_mask;
	if (df->l4_type == DP_IP_PROTO_TCP)
	{
		hairpin_pattern_cnt = insert_tcp_match_pattern(hairpin_pattern, hairpin_pattern_cnt,
											   &tcp_spec, &tcp_mask,
											   df->src_port, df->dst_port);
		pattern_cnt = insert_tcp_match_pattern(pattern, pattern_cnt,
											   &tcp_spec, &tcp_mask,
											   df->src_port, df->dst_port);
	}

	struct rte_flow_item_udp udp_spec;
	struct rte_flow_item_udp udp_mask;
	if (df->l4_type == DP_IP_PROTO_UDP)
	{
		hairpin_pattern_cnt = insert_udp_match_pattern(hairpin_pattern, hairpin_pattern_cnt,
											   &udp_spec, &udp_mask,
											   df->src_port, df->dst_port);
		pattern_cnt = insert_udp_match_pattern(pattern, pattern_cnt,
											   &udp_spec, &udp_mask,
											   df->src_port, df->dst_port);
	}

	struct rte_flow_item_icmp icmp_spec;
	struct rte_flow_item_icmp icmp_mask;
	if (df->l4_type == DP_IP_PROTO_ICMP)
	{
		hairpin_pattern_cnt = insert_icmp_match_pattern(hairpin_pattern, hairpin_pattern_cnt,
												&icmp_spec, &icmp_mask,
												df->icmp_type);
		pattern_cnt = insert_icmp_match_pattern(pattern, pattern_cnt,
												&icmp_spec, &icmp_mask,
												df->icmp_type);
	}

	struct rte_flow_item_icmp6 icmp6_spec;
	struct rte_flow_item_icmp6 icmp6_mask;
	if (df->l4_type == DP_IP_PROTO_ICMPV6)
	{
		hairpin_pattern_cnt = insert_icmpv6_match_pattern(hairpin_pattern, hairpin_pattern_cnt,
												  &icmp6_spec, &icmp6_mask,
												  df->icmp_type);
		pattern_cnt = insert_icmpv6_match_pattern(pattern, pattern_cnt,
												  &icmp6_spec, &icmp6_mask,
												  df->icmp_type);
	}

	// create flow match patterns -- end
	hairpin_pattern_cnt = insert_end_match_pattern(hairpin_pattern, hairpin_pattern_cnt);
	pattern_cnt = insert_end_match_pattern(pattern, pattern_cnt);


	/*Firstly install a flow rule to move packet to hairpin rxq*/
	// struct rte_flow_action_mark mark_action;
	// hairpin_action_cnt = create_packet_mark_action(hairpin_action, hairpin_action_cnt, &mark_action, df->tun_info.dst_vni);
	// hairpin_action_cnt = create_packet_mark_action(hairpin_action, hairpin_action_cnt, &mark_action, 0x64);
	
	// struct rte_flow_action_set_tag tag_action;
	// hairpin_action_cnt = create_set_tag_action(hairpin_action, hairpin_action_cnt, &tag_action, df->tun_info.dst_vni,0);

	// struct rte_flow_action_set_meta meta_action;
	// hairpin_action_cnt = create_set_meta_action(hairpin_action, hairpin_action_cnt, &meta_action, df->tun_info.dst_vni);

	struct rte_flow_action_set_mac set_mac_action;
	struct rte_ether_addr	e_addr;
	memcpy(e_addr.addr_bytes, vni_in_mac_addr, sizeof(RTE_ETHER_ADDR_LEN));
	hairpin_action_cnt = create_dst_mac_set_action(hairpin_action, hairpin_action_cnt, &set_mac_action, &e_addr);

	struct rte_flow_action_queue queue_action;
	uint16_t hairpin_rx_queue_id = DP_NR_STD_RX_QUEUES;
 	hairpin_action_cnt = create_redirect_queue_action(hairpin_action, hairpin_action_cnt, &queue_action, hairpin_rx_queue_id);

	// create flow action -- end
	hairpin_action_cnt = create_end_action(hairpin_action, hairpin_action_cnt);

	// validate and install rte flow
	create_rte_flow_rule_attr(&attr, 0, 0, 1, 0, 0);
	struct rte_flow *hairpin_flow = NULL;
	hairpin_flow = validate_and_install_rte_flow(m->port, &attr, hairpin_pattern, hairpin_action, df);
	if (!hairpin_flow)
	{
		// free_allocated_agectx(agectx);
		printf("failed to install hairpin queue flow rule \n");
		return 0;
	}

	// create flow action -- raw decap
	struct rte_flow_action_raw_decap raw_decap;
	action_cnt = create_raw_decap_action(action, action_cnt,
										 &raw_decap, NULL, sizeof(struct rte_ether_hdr));


	// create flow action -- raw encap
	uint8_t ipip_encap_hdr[DP_TUNN_IPIP_ENCAP_SIZE];
	memset(ipip_encap_hdr, 0, DP_TUNN_IPIP_ENCAP_SIZE);

	uint8_t geneve_encap_hdr[DP_TUNN_GENEVE_ENCAP_SIZE];
	memset(geneve_encap_hdr, 0, DP_TUNN_GENEVE_ENCAP_SIZE);

	uint8_t *encap_hdr = NULL;
	size_t raw_encap_size = 0;
	if (get_overlay_type() == DP_FLOW_OVERLAY_TYPE_GENEVE)
	{
		encap_hdr = geneve_encap_hdr;
		raw_encap_size = DP_TUNN_GENEVE_ENCAP_SIZE;
	}
	else
	{
		encap_hdr = ipip_encap_hdr;
		raw_encap_size = DP_TUNN_IPIP_ENCAP_SIZE;
	}

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

	if (get_overlay_type() == DP_FLOW_OVERLAY_TYPE_GENEVE)
	{
		struct rte_udp_hdr *new_udp_hdr = (struct rte_udp_hdr *)(new_ipv6_hdr + 1);
		new_udp_hdr->src_port = df->tun_info.src_port;
		new_udp_hdr->dst_port = df->tun_info.dst_port;

		struct rte_flow_item_geneve *new_geneve_hdr = (struct rte_flow_item_geneve *)(new_udp_hdr + 1);
		rte_memcpy(new_geneve_hdr->vni, &df->tun_info.dst_vni, sizeof(new_geneve_hdr->vni));
		new_geneve_hdr->ver_opt_len_o_c_rsvd0 = 0;
		new_geneve_hdr->protocol = htons(df->l3_type);
	}

	action_cnt = create_raw_encap_action(action, action_cnt,
										 &raw_encap, encap_hdr, raw_encap_size);

	// create flow action -- age
	struct flow_age_ctx *agectx = rte_zmalloc("age_ctx", sizeof(struct flow_age_ctx), RTE_CACHE_LINE_SIZE);
	struct rte_flow_action_age flow_age;
	if (!agectx)
		return 0;
	action_cnt = create_flow_age_action(action, action_cnt,
										&flow_age, 60, agectx);

	// create flow action -- send to port
	// struct rte_flow_action_port_id send_to_port;
	// action_cnt = create_send_to_port_action(action, action_cnt,
	// 										&send_to_port, df->nxt_hop);

	// create flow action -- end
	action_cnt = create_end_action(action, action_cnt);

	// validate and install rte flow
	struct rte_flow *flow = NULL;
	create_rte_flow_rule_attr(&attr, 0, 0, 0, 1, 0);
	uint16_t peer_pf_port_id =  dp_get_pf1_port_id();
	flow = validate_and_install_rte_flow(peer_pf_port_id, &attr, pattern, action, df);
	if (!flow)
	{
		free_allocated_agectx(agectx);
		return 0;
	}

	// config the content of agectx
	config_allocated_agectx(agectx, m->port, df, flow);
	return 1;
}

static __rte_always_inline int dp_handle_tunnel_decap_offload(struct rte_mbuf *m, struct dp_flow *df)
{

	struct underlay_conf *u_conf = get_underlay_conf();

	struct rte_flow_attr attr;
	create_rte_flow_rule_attr(&attr, 0, 0, 1, 0, 1);

	struct rte_flow_item pattern[DP_TUNN_OPS_OFFLOAD_MAX_PATTERN];
	int pattern_cnt = 0;
	struct rte_flow_action action[DP_TUNN_OPS_OFFLOAD_MAX_ACTION];
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

	if (get_overlay_type() == DP_FLOW_OVERLAY_TYPE_GENEVE)
	{

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

	if (df->l3_type == RTE_ETHER_TYPE_IPV6)
	{
		pattern_cnt = insert_ipv6_match_pattern(pattern, pattern_cnt,
												&ol_ipv6_spec, &ol_ipv6_mask,
												NULL, 0,
												df->dst.dst_addr6, sizeof(ol_ipv6_spec.hdr.dst_addr),
												df->l4_type);
	}
	else
	{
		pattern_cnt = insert_ipv4_match_pattern(pattern, pattern_cnt,
												&ol_ipv4_spec, &ol_ipv4_mask,
												df, DP_IS_DST);
	}

	// create flow match patterns -- inner packet, tcp, udp or icmp/icmpv6
	struct rte_flow_item_tcp tcp_spec;
	struct rte_flow_item_tcp tcp_mask;
	if (df->l4_type == DP_IP_PROTO_TCP)
	{
		pattern_cnt = insert_tcp_match_pattern(pattern, pattern_cnt,
											   &tcp_spec, &tcp_mask,
											   df->src_port, df->dst_port);
	}

	struct rte_flow_item_udp udp_spec;
	struct rte_flow_item_udp udp_mask;
	if (df->l4_type == DP_IP_PROTO_UDP)
	{
		pattern_cnt = insert_udp_match_pattern(pattern, pattern_cnt,
											   &udp_spec, &udp_mask,
											   df->src_port, df->dst_port);
	}

	struct rte_flow_item_icmp icmp_spec;
	struct rte_flow_item_icmp icmp_mask;
	if (df->l4_type == DP_IP_PROTO_ICMP)
	{
		pattern_cnt = insert_icmp_match_pattern(pattern, pattern_cnt,
												&icmp_spec, &icmp_mask,
												df->icmp_type);
	}

	struct rte_flow_item_icmp6 icmp6_spec;
	struct rte_flow_item_icmp6 icmp6_mask;
	if (df->l4_type == DP_IP_PROTO_ICMPV6)
	{
		pattern_cnt = insert_icmpv6_match_pattern(pattern, pattern_cnt,
												  &icmp6_spec, &icmp6_mask,
												  df->icmp_type);
	}

	// create flow match patterns -- end
	pattern_cnt = insert_end_match_pattern(pattern, pattern_cnt);

	// create flow action -- raw decap
	struct rte_flow_action_raw_decap raw_decap;
	if (get_overlay_type() == DP_FLOW_OVERLAY_TYPE_GENEVE)
	{
		action_cnt = create_raw_decap_action(action, action_cnt,
											 &raw_decap, NULL, DP_TUNN_GENEVE_ENCAP_SIZE);
	}
	else
	{
		action_cnt = create_raw_decap_action(action, action_cnt,
											 &raw_decap, NULL, DP_TUNN_IPIP_ENCAP_SIZE);
	}

	// create flow action -- raw encap
	uint8_t eth_hdr[sizeof(struct rte_ether_hdr)];
	struct rte_flow_action_raw_encap raw_encap;

	struct rte_ether_hdr *new_eth_hdr = (struct rte_ether_hdr *)eth_hdr;
	rte_ether_addr_copy(dp_get_neigh_mac(df->nxt_hop), &new_eth_hdr->dst_addr);
	rte_ether_addr_copy(dp_get_mac(df->nxt_hop), &new_eth_hdr->src_addr);
	new_eth_hdr->ether_type = htons(df->l3_type);

	action_cnt = create_raw_encap_action(action, action_cnt,
										 &raw_encap, eth_hdr, sizeof(struct rte_ether_hdr));

	// create flow action -- age
	struct flow_age_ctx *agectx = rte_zmalloc("age_ctx", sizeof(struct flow_age_ctx), RTE_CACHE_LINE_SIZE);
	struct rte_flow_action_age flow_age;
	if (!agectx)
		return 0;

	action_cnt = create_flow_age_action(action, action_cnt,
											&flow_age, 60, agectx);

	// create flow action -- send to port
	struct rte_flow_action_port_id send_to_port;
	action_cnt = create_send_to_port_action(action, action_cnt,
											&send_to_port, df->nxt_hop);
	// create flow action -- end
	action_cnt = create_end_action(action, action_cnt);

	// validate and install rte flow
	struct rte_flow *flow = NULL;
	flow = validate_and_install_rte_flow(m->port, &attr, pattern, action, df);
	if (!flow)
	{
		free_allocated_agectx(agectx);
		return 0;
	}

	// config the content of agectx
	config_allocated_agectx(agectx, m->port, df, flow);
	return 1;
}

static __rte_always_inline int dp_handle_tunnel_decap_hairpin_offload(struct rte_mbuf *m, struct dp_flow *df)
{

	struct underlay_conf *u_conf = get_underlay_conf();

	struct rte_flow_attr attr;
	create_rte_flow_rule_attr(&attr, 0, 0, 1, 0, 0);

	struct rte_flow_item pattern[DP_TUNN_OPS_OFFLOAD_MAX_PATTERN];
	int pattern_cnt = 0;
	// struct rte_flow_item hairpin_pattern[DP_TUNN_OPS_OFFLOAD_MAX_PATTERN];
	// int hairpin_pattern_cnt = 0;
	struct rte_flow_action action[DP_TUNN_OPS_OFFLOAD_MAX_ACTION];
	int action_cnt = 0;
	struct rte_flow_action hairpin_action[DP_TUNN_OPS_OFFLOAD_MAX_ACTION];
	int hairpin_action_cnt = 0;
	memset(pattern, 0, sizeof(pattern));
	// memset(hairpin_pattern, 0, sizeof(hairpin_pattern));
	memset(action, 0, sizeof(action));
	memset(hairpin_action, 0, sizeof(hairpin_action));
	
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

	if (get_overlay_type() == DP_FLOW_OVERLAY_TYPE_GENEVE)
	{

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

	if (df->l3_type == RTE_ETHER_TYPE_IPV6)
	{
		pattern_cnt = insert_ipv6_match_pattern(pattern, pattern_cnt,
												&ol_ipv6_spec, &ol_ipv6_mask,
												NULL, 0,
												df->dst.dst_addr6, sizeof(ol_ipv6_spec.hdr.dst_addr),
												df->l4_type);
	}
	else
	{
		pattern_cnt = insert_ipv4_match_pattern(pattern, pattern_cnt,
												&ol_ipv4_spec, &ol_ipv4_mask,
												df, DP_IS_DST);
	}

	// create flow match patterns -- inner packet, tcp, udp or icmp/icmpv6
	struct rte_flow_item_tcp tcp_spec;
	struct rte_flow_item_tcp tcp_mask;
	if (df->l4_type == DP_IP_PROTO_TCP)
	{
		pattern_cnt = insert_tcp_match_pattern(pattern, pattern_cnt,
											   &tcp_spec, &tcp_mask,
											   df->src_port, df->dst_port);
	}

	struct rte_flow_item_udp udp_spec;
	struct rte_flow_item_udp udp_mask;
	if (df->l4_type == DP_IP_PROTO_UDP)
	{
		pattern_cnt = insert_udp_match_pattern(pattern, pattern_cnt,
											   &udp_spec, &udp_mask,
											   df->src_port, df->dst_port);
	}

	struct rte_flow_item_icmp icmp_spec;
	struct rte_flow_item_icmp icmp_mask;
	if (df->l4_type == DP_IP_PROTO_ICMP)
	{
		pattern_cnt = insert_icmp_match_pattern(pattern, pattern_cnt,
												&icmp_spec, &icmp_mask,
												df->icmp_type);
	}

	struct rte_flow_item_icmp6 icmp6_spec;
	struct rte_flow_item_icmp6 icmp6_mask;
	if (df->l4_type == DP_IP_PROTO_ICMPV6)
	{
		pattern_cnt = insert_icmpv6_match_pattern(pattern, pattern_cnt,
												  &icmp6_spec, &icmp6_mask,
												  df->icmp_type);
	}

	// create flow match patterns -- end
	pattern_cnt = insert_end_match_pattern(pattern, pattern_cnt);

	/*Firstly, move this packets to the right hairpin rx queue of pf, so as to be moved to vf*/
	struct rte_flow_action_queue queue_action;
	uint16_t hairpin_rx_queue_id = get_pf_hairpin_rx_queue((uint16_t)df->nxt_hop);
 	hairpin_action_cnt = create_redirect_queue_action(hairpin_action, hairpin_action_cnt, &queue_action, hairpin_rx_queue_id);

	// create flow action -- end
	hairpin_action_cnt = create_end_action(hairpin_action, hairpin_action_cnt);

	// validate and install rte flow
	create_rte_flow_rule_attr(&attr, 0, 0, 1, 0, 0);
	struct rte_flow *hairpin_flow = NULL;
	hairpin_flow = validate_and_install_rte_flow(m->port, &attr, pattern, hairpin_action, df);
	if (!hairpin_flow)
	{
		// free_allocated_agectx(agectx);
		printf("failed to install hairpin queue flow rule \n");
		return 0;
	}

	// create flow action -- raw decap
	struct rte_flow_action_raw_decap raw_decap;
	if (get_overlay_type() == DP_FLOW_OVERLAY_TYPE_GENEVE)
	{
		action_cnt = create_raw_decap_action(action, action_cnt,
											 &raw_decap, NULL, DP_TUNN_GENEVE_ENCAP_SIZE);
	}
	else
	{
		action_cnt = create_raw_decap_action(action, action_cnt,
											 &raw_decap, NULL, DP_TUNN_IPIP_ENCAP_SIZE);
	}

	// create flow action -- raw encap
	uint8_t eth_hdr[sizeof(struct rte_ether_hdr)];
	struct rte_flow_action_raw_encap raw_encap;

	struct rte_ether_hdr *new_eth_hdr = (struct rte_ether_hdr *)eth_hdr;
	rte_ether_addr_copy(dp_get_neigh_mac(df->nxt_hop), &new_eth_hdr->dst_addr);
	rte_ether_addr_copy(dp_get_mac(df->nxt_hop), &new_eth_hdr->src_addr);
	new_eth_hdr->ether_type = htons(df->l3_type);

	action_cnt = create_raw_encap_action(action, action_cnt,
										 &raw_encap, eth_hdr, sizeof(struct rte_ether_hdr));

	// create flow action -- age
	struct flow_age_ctx *agectx = rte_zmalloc("age_ctx", sizeof(struct flow_age_ctx), RTE_CACHE_LINE_SIZE);
	struct rte_flow_action_age flow_age;
	if (!agectx)
		return 0;

	action_cnt = create_flow_age_action(action, action_cnt,
											&flow_age, 60, agectx);

	// create flow action -- send to port
	// struct rte_flow_action_port_id send_to_port;
	// action_cnt = create_send_to_port_action(action, action_cnt,
	// 										&send_to_port, df->nxt_hop);
	// create flow action -- end
	action_cnt = create_end_action(action, action_cnt);

	// validate and install rte flow
	struct rte_flow *flow = NULL;
	create_rte_flow_rule_attr(&attr, 0, 0, 0, 1, 0);
	flow = validate_and_install_rte_flow((uint16_t)df->nxt_hop, &attr, pattern, action, df);
	if (!flow)
	{
		// free_allocated_agectx(agectx);
		return 0;
	}

	// config the content of agectx
	config_allocated_agectx(agectx, m->port, df, flow);
	return 1;
}


static __rte_always_inline int dp_handle_local_traffic_forward(struct rte_mbuf *m, struct dp_flow *df)
{

	struct rte_flow_attr attr;
	create_rte_flow_rule_attr(&attr, 0, 0, 1, 0, 1);

	struct rte_flow_item pattern[DP_TUNN_OPS_OFFLOAD_MAX_PATTERN];
	int pattern_cnt = 0;
	struct rte_flow_action action[DP_TUNN_OPS_OFFLOAD_MAX_ACTION];
	int action_cnt = 0;
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

	if (df->l3_type == RTE_ETHER_TYPE_IPV6)
	{
		pattern_cnt = insert_ipv6_match_pattern(pattern, pattern_cnt,
												&ol_ipv6_spec, &ol_ipv6_mask,
												NULL, 0,
												df->dst.dst_addr6, sizeof(ol_ipv6_spec.hdr.dst_addr),
												df->l4_type);
	}
	else
	{
		pattern_cnt = insert_ipv4_match_pattern(pattern, pattern_cnt,
												&ol_ipv4_spec, &ol_ipv4_mask,
												df, DP_IS_DST);
	}

	// create flow match patterns -- inner packet, tcp, udp or icmp/icmpv6
	struct rte_flow_item_tcp tcp_spec;
	struct rte_flow_item_tcp tcp_mask;
	if (df->l4_type == DP_IP_PROTO_TCP)
	{
		pattern_cnt = insert_tcp_match_pattern(pattern, pattern_cnt,
											   &tcp_spec, &tcp_mask,
											   df->src_port, df->dst_port);
	}

	struct rte_flow_item_udp udp_spec;
	struct rte_flow_item_udp udp_mask;
	if (df->l4_type == DP_IP_PROTO_UDP)
	{
		pattern_cnt = insert_udp_match_pattern(pattern, pattern_cnt,
											   &udp_spec, &udp_mask,
											   df->src_port, df->dst_port);
	}

	struct rte_flow_item_icmp icmp_spec;
	struct rte_flow_item_icmp icmp_mask;
	if (df->l4_type == DP_IP_PROTO_ICMP)
	{
		pattern_cnt = insert_icmp_match_pattern(pattern, pattern_cnt,
												&icmp_spec, &icmp_mask,
												df->icmp_type);
	}

	struct rte_flow_item_icmp6 icmp6_spec;
	struct rte_flow_item_icmp6 icmp6_mask;
	if (df->l4_type == DP_IP_PROTO_ICMPV6)
	{
		pattern_cnt = insert_icmpv6_match_pattern(pattern, pattern_cnt,
												  &icmp6_spec, &icmp6_mask,
												  df->icmp_type);
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

	struct rte_flow_action_set_ipv4 set_ipv4;
	if (df->flags.nat == DP_NAT_CHG_DST_IP)
		action_cnt = create_ipv4_set_action(action, action_cnt,
										    &set_ipv4, df->dst.dst_addr, DP_IS_DST);

	if (df->flags.nat == DP_NAT_CHG_SRC_IP)
		action_cnt = create_ipv4_set_action(action, action_cnt,
										    &set_ipv4, df->src.src_addr, DP_IS_SRC);

	// create flow action -- age
	struct flow_age_ctx *agectx = rte_zmalloc("age_ctx", sizeof(struct flow_age_ctx), RTE_CACHE_LINE_SIZE);
	struct rte_flow_action_age flow_age;
	if (!agectx)
		return 0;
	action_cnt = create_flow_age_action(action, action_cnt,
										&flow_age, 60, agectx);
	// create flow action -- send to port
	struct rte_flow_action_port_id send_to_port;
	action_cnt = create_send_to_port_action(action, action_cnt,
											&send_to_port, df->nxt_hop);
	// create flow action -- end
	action_cnt = create_end_action(action, action_cnt);

	// validate and install rte flow
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

int dp_handle_traffic_forward_offloading(struct rte_mbuf *m, struct dp_flow *df)
{

	if (df->flags.flow_type == DP_FLOW_TYPE_LOCAL)
		return dp_handle_local_traffic_forward(m, df);

	if (df->flags.flow_type == DP_FLOW_TYPE_INCOMING)
		return dp_handle_tunnel_decap_offload(m, df);

	if (df->flags.flow_type == DP_FLOW_TYPE_OUTGOING) {
		if (df->nxt_hop == dp_get_pf0_port_id())
			return dp_handle_tunnel_encap_offload(m, df);
		else
			return dp_handle_tunnel_encap_hairpin_offload(m,df);
	}

	return 0;
}
