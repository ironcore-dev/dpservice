#include "rte_flow/dp_rte_flow_traffic_forward.h"
#include "dp_conf.h"
#include "dp_error.h"
#include "dp_log.h"
#include "dp_lpm.h"
#include "dp_nat.h"
#include "nodes/ipv6_nd_node.h"
#include "rte_flow/dp_rte_flow_helpers.h"

#define DP_IPIP_ENCAP_HEADER_SIZE (sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv6_hdr))

// it is used by pf to install a rule to move hairpin packets to the right rx hairpin queue
static const struct rte_flow_attr dp_flow_pf_attr_ingress = {
	.group = DP_RTE_FLOW_DEFAULT_GROUP,
	.priority = 0,
	.ingress = 1,
	.egress = 0,
	.transfer = 0,
};

// it is used by vf to install a rule to move hairpin packets to the right rx hairpin queue
static const struct rte_flow_attr dp_flow_vf_attr_ingress = {
	.group = DP_RTE_FLOW_DEFAULT_GROUP,
	.priority = 0,
	.ingress = 1,
	.egress = 0,
	.transfer = 0,
};

// it is used during the encap operation to install a encap/decap rule on pf to process pkts arriving to tx hairpin queue
static const struct rte_flow_attr dp_flow_attr_egress = {
	.group = DP_RTE_FLOW_DEFAULT_GROUP,
	.priority = 0,
	.ingress = 0,
	.egress = 1,
	.transfer = 0,
};

// it is used during the decap operation on pf to install a redirecting rule
// to point a specific flow to either capturing rule or vnet rule
static const struct rte_flow_attr dp_flow_pf_attr_transfer_special = {
	.group = DP_RTE_FLOW_DEFAULT_GROUP,
	.priority = 0,
	.ingress = 0,
	.egress = 0,
	.transfer = 1,
}; 

// it is used during the decap/decap operation to install a decap/encap rule to transfer pkts
static const struct rte_flow_attr dp_flow_attr_transfer_multi_stage = {
	.group = DP_RTE_FLOW_VNET_GROUP,
	.priority = 0,
	.ingress = 0,
	.egress = 0,
	.transfer = 1,
};

// it is used during the decap/encap operation to install a decap/encap rule to transfer pkts
static const struct rte_flow_attr dp_flow_attr_transfer_single_stage = {
	.group = DP_RTE_FLOW_DEFAULT_GROUP,
	.priority = 0,
	.ingress = 0,
	.egress = 0,
	.transfer = 1,
};


static __rte_always_inline struct flow_age_ctx *allocate_agectx(void)
{
	struct flow_age_ctx *agectx;

	agectx = rte_zmalloc("age_ctx", sizeof(struct flow_age_ctx), RTE_CACHE_LINE_SIZE);
	if (!agectx)
		DPS_LOG_ERR("Failed to allocate age context");

	return agectx;
}

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

static __rte_always_inline int dp_create_age_indirect_action(uint16_t port_id,
															 const struct rte_flow_attr *attr,
															 const struct rte_flow_action *age_action,
															 struct flow_value *conntrack,
															 struct flow_age_ctx *agectx)
{
	struct rte_flow_indir_action_conf age_indirect_conf = {
		.ingress = attr->ingress,
		.egress = attr->egress,
		.transfer = attr->transfer,
	};
	struct rte_flow_error error;
	struct rte_flow_action_handle *result;
	int ret;

	result = rte_flow_action_handle_create(port_id, &age_indirect_conf, age_action, &error);
	if (!result) {
		DPS_LOG_ERR("Flow's age cannot be configured as indirect", DP_LOG_FLOW_ERROR(error.message));
		return DP_ERROR;
	}

	if (DP_FAILED(dp_add_rte_age_ctx(conntrack, agectx))) {
		DPS_LOG_ERR("Failed to store agectx in conntrack object");
		ret = rte_flow_action_handle_destroy(port_id, result, &error);
		if (DP_FAILED(ret))
			DPS_LOG_ERR("Failed to remove an indirect action",
						DP_LOG_PORTID(port_id), DP_LOG_FLOW_ERROR(error.message), DP_LOG_RET(ret));
		return DP_ERROR;
	}

	agectx->handle = result;
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
	struct rte_flow_error error;
	int ret;

	if (df->l4_type == IPPROTO_TCP)
		if (DP_FAILED(dp_create_age_indirect_action(port_id, attr, age_action, df->conntrack, agectx)))
			return DP_ERROR;

	ret = dp_install_rte_flow_with_age(port_id, attr, pattern, actions, df->conntrack, agectx);
	if (DP_FAILED(ret)) {
		DPS_LOG_ERR("Failed to install aging rte flow", DP_LOG_RET(ret));
		if (df->l4_type == IPPROTO_TCP) {
			// ignore errors, just added this
			dp_del_rte_age_ctx(df->conntrack, agectx);
			rte_flow_action_handle_destroy(port_id, agectx->handle, &error);
		}
	}
	return ret;
}

static __rte_always_inline void dp_create_ipip_encap_header(uint8_t raw_hdr[DP_IPIP_ENCAP_HEADER_SIZE],
															const struct dp_flow *df,
															const uint8_t *src_ip6)
{
	struct rte_ether_hdr *encap_eth_hdr = (struct rte_ether_hdr *)raw_hdr;
	struct rte_ipv6_hdr *encap_ipv6_hdr = (struct rte_ipv6_hdr *)(&raw_hdr[sizeof(struct rte_ether_hdr)]);

	rte_ether_addr_copy(dp_get_neigh_mac(df->nxt_hop), &encap_eth_hdr->dst_addr);
	rte_ether_addr_copy(dp_get_mac(df->nxt_hop), &encap_eth_hdr->src_addr);
	encap_eth_hdr->ether_type = htons(RTE_ETHER_TYPE_IPV6);

	encap_ipv6_hdr->vtc_flow = htonl(DP_IP6_VTC_FLOW);
	encap_ipv6_hdr->payload_len = 0;
	encap_ipv6_hdr->proto = df->tun_info.proto_id;
	encap_ipv6_hdr->hop_limits = DP_IP6_HOP_LIMIT;
	rte_memcpy(encap_ipv6_hdr->src_addr, src_ip6, sizeof(encap_ipv6_hdr->src_addr));
	rte_memcpy(encap_ipv6_hdr->dst_addr, df->tun_info.ul_dst_addr6, sizeof(encap_ipv6_hdr->dst_addr));
}

static __rte_always_inline int dp_offload_handle_tunnel_encap_traffic(struct rte_mbuf *m, struct dp_flow *df)
{
	// match pattern for outgoing VF packets
	struct rte_flow_item_eth eth_spec; // #1
	union dp_flow_item_l3 l3_spec;     // #2
	union dp_flow_item_l4 l4_spec;     // #3
	struct rte_flow_item pattern[4];   // + end
	int pattern_cnt = 0;

	// hairpin uses the same items as above, only with the eth_spec being different
	struct rte_flow_item_eth hairpin_eth_spec;
	struct rte_flow_item hairpin_pattern[4];
	int hairpin_pattern_cnt = 0;

	// tunnel encap action steps
	struct rte_flow_action_set_ipv4 set_ipv4;    // #1 (optional)
	struct rte_flow_action_set_tp set_tp;        // #2 (optional)
	struct rte_flow_action_raw_decap raw_decap;  // #3
	struct rte_flow_action_raw_encap raw_encap;  // #4
	struct rte_flow_action_age flow_age;         // #5
	struct rte_flow_action_port_id send_to_port; // #6 (optional)
	struct rte_flow_action actions[7];            // + end
	int action_cnt = 0;

	// hairpin action is different - redirects the flow
	struct rte_flow_action_set_mac hairpin_set_mac; // #1
	struct rte_flow_action_queue hairpin_redirect;  // #2
	struct rte_flow_action_age hairpin_flow_age;    // #3
	struct rte_flow_action hairpin_actions[4];       // + end
	int hairpin_action_cnt = 0;

	// misc variables needed to create the flow
	struct rte_ether_addr vni_in_mac_addr;
	struct rte_flow_action *age_action;
	struct rte_flow_action *hairpin_age_action;
	struct flow_age_ctx *agectx;
	struct flow_age_ctx *hairpin_agectx = NULL;
	uint8_t raw_encap_hdr[DP_IPIP_ENCAP_HEADER_SIZE];
	const struct rte_flow_attr *attr;
	uint16_t t_port_id;
	bool cross_pf_port;

	cross_pf_port = df->nxt_hop != dp_port_get_pf0_id();

	// Match vf packets (and possibly modified vf packets embedded with vni info)
	if (cross_pf_port) {
		dp_set_eth_flow_item(&hairpin_pattern[hairpin_pattern_cnt++], &hairpin_eth_spec, htons(df->l3_type));
		memset(vni_in_mac_addr.addr_bytes, 0, sizeof(vni_in_mac_addr));
		memcpy(vni_in_mac_addr.addr_bytes, &df->tun_info.dst_vni, 4);
		dp_set_eth_dst_flow_item(&pattern[pattern_cnt++], &eth_spec, &vni_in_mac_addr, htons(df->l3_type));
	} else
		dp_set_eth_flow_item(&pattern[pattern_cnt++], &eth_spec, htons(df->l3_type));

	// encapsulating, there is only overlay addressing
	if (df->l3_type == RTE_ETHER_TYPE_IPV6)
		dp_set_ipv6_dst_flow_item(&pattern[pattern_cnt++], &l3_spec.ipv6, df->dst.dst_addr6, df->l4_type);
	else
		dp_set_ipv4_dst_flow_item(&pattern[pattern_cnt++], &l3_spec.ipv4, df->dst.dst_addr, df->l4_type);
	if (cross_pf_port)
		hairpin_pattern[hairpin_pattern_cnt++] = pattern[pattern_cnt-1];

	if (DP_FAILED(dp_set_l4_flow_item(&pattern[pattern_cnt++], &l4_spec, df)))
		return DP_ERROR;
	if (cross_pf_port)
		hairpin_pattern[hairpin_pattern_cnt++] = pattern[pattern_cnt-1];

	dp_set_end_flow_item(&pattern[pattern_cnt++]);
	if (cross_pf_port)
		hairpin_pattern[hairpin_pattern_cnt++] = pattern[pattern_cnt-1];

	/* First, install a flow rule to modify mac address to embed vni info and move packet to hairpin rxq */
	if (cross_pf_port) {
		// set proper ethernet address
		dp_set_dst_mac_set_action(&hairpin_actions[hairpin_action_cnt++], &hairpin_set_mac, &vni_in_mac_addr);
		// move packet to hairpin rx queue
		dp_set_redirect_queue_action(&hairpin_actions[hairpin_action_cnt++], &hairpin_redirect, DP_NR_STD_RX_QUEUES);
		// make flow aging work
		hairpin_agectx = allocate_agectx();
		if (!hairpin_agectx)
			return DP_ERROR;
		hairpin_age_action = &hairpin_actions[hairpin_action_cnt++];
		dp_set_flow_age_action(hairpin_age_action, &hairpin_flow_age, df->conntrack->timeout_value, hairpin_agectx);

		dp_set_end_action(&hairpin_actions[hairpin_action_cnt++]);

		if (DP_FAILED(dp_install_rte_flow_with_indirect(m->port, &dp_flow_vf_attr_ingress,
														hairpin_pattern, hairpin_actions,
														hairpin_age_action, df, hairpin_agectx))
		) {
			dp_destroy_rte_flow_agectx(hairpin_agectx);
			DPS_LOG_ERR("Failed to install hairpin queue flow rule on VF", DP_LOG_PORTID(m->port));
			return DP_ERROR;
		}
		DPS_LOG_DEBUG("Installed a flow rule to move pkts to hairpin rx queue", DP_LOG_PORTID(m->port));
	}

	// replace source ip if vip-nat/network-nat is enabled
	if (df->flags.nat == DP_NAT_CHG_SRC_IP) {
		dp_set_ipv4_set_src_action(&actions[action_cnt++], &set_ipv4, df->nat_addr);
		// also replace source port if network-nat is enabled
		if (df->conntrack->nf_info.nat_type == DP_FLOW_NAT_TYPE_NETWORK_LOCAL)
			dp_set_trans_proto_set_src_action(&actions[action_cnt++], &set_tp, htons(df->nat_port));
	}

	// standard actions do not have the power to do what needs to be done here
	// thus a raw decap (to get a 'naked' packet) and raw encap is used
	dp_set_raw_decap_action(&actions[action_cnt++], &raw_decap, NULL, sizeof(struct rte_ether_hdr));
	dp_create_ipip_encap_header(raw_encap_hdr, df, dp_get_port_ul_ip6(m->port));
	dp_set_raw_encap_action(&actions[action_cnt++], &raw_encap, raw_encap_hdr, sizeof(raw_encap_hdr));

	// make flow aging work
	agectx = allocate_agectx();
	if (!agectx) {
		if (hairpin_agectx)
			dp_destroy_rte_flow_agectx(hairpin_agectx);
		return DP_ERROR;
	}

	age_action = &actions[action_cnt++];
	dp_set_flow_age_action(age_action, &flow_age, df->conntrack->timeout_value, agectx);

	// send to the right port (unless already handled by the hairpin)
	if (!cross_pf_port)
		dp_set_send_to_port_action(&actions[action_cnt++], &send_to_port, df->nxt_hop);

	dp_set_end_action(&actions[action_cnt++]);

	// install rte flow to the right port
	if (cross_pf_port) {
		attr = &dp_flow_attr_egress;
		t_port_id = dp_port_get_pf1_id();
	} else {
		if (dp_port_get(m->port)->captured)
			attr = &dp_flow_attr_transfer_multi_stage;
		else
			attr = &dp_flow_attr_transfer_single_stage;
		t_port_id = m->port;
	}
	if (DP_FAILED(dp_install_rte_flow_with_indirect(t_port_id, attr,
													pattern, actions,
													age_action, df, agectx))
	) {
		dp_destroy_rte_flow_agectx(agectx);
		if (hairpin_agectx)
			dp_destroy_rte_flow_agectx(hairpin_agectx);
		return DP_ERROR;
	}

	if (cross_pf_port)
		DPS_LOG_DEBUG("Installed cross pf encap flow rules", DP_LOG_PORTID(m->port));
	else
		DPS_LOG_DEBUG("Installed encap flow rule on VF", DP_LOG_PORTID(m->port));

	return DP_OK;
}

static __rte_always_inline int dp_offload_handle_tunnel_decap_traffic(struct rte_mbuf *m, struct dp_flow *df)
{
	// match pattern for incoming tunneled packets
	struct rte_flow_item_eth eth_spec;   // #1
	struct rte_flow_item_ipv6 ipv6_spec; // #2
	union dp_flow_item_l3 l3_spec;       // #3
	union dp_flow_item_l4 l4_spec;       // #4
	struct rte_flow_item pattern[5];     // + end
	int pattern_cnt = 0;

	// tunnel decap action steps
	struct rte_flow_action_raw_decap raw_decap;  // #1
	struct rte_flow_action_raw_encap raw_encap;  // #2
	struct rte_flow_action_set_ipv4 set_ipv4;    // #3 (optional)
	struct rte_flow_action_set_tp set_tp;        // #4 (optional)
	struct rte_flow_action_age flow_age;         // #5
	struct rte_flow_action_queue redirect_queue; // #6 (choose one)
	struct rte_flow_action_port_id send_to_port; // #6 (choose one)
	struct rte_flow_action actions[7];            // + end
	int action_cnt = 0;

	struct rte_flow_action_jump jump_action; // 1
	struct rte_flow_action_age flow_age_special; 
	struct rte_flow_action special_moni_action[3];
	int special_moni_action_cnt = 0;

	// misc variables needed to create the flow
	struct flow_age_ctx *agectx, *agectx_special;
	struct rte_flow_action *age_action, *age_action_special;
	struct dp_port *port;
	struct rte_ether_hdr new_eth_hdr;
	rte_be32_t actual_ol_ipv4_addr;
	bool cross_pf_port;
	const struct rte_flow_attr *attr =  &dp_flow_attr_transfer_single_stage;

	cross_pf_port = m->port != dp_port_get_pf0_id();
	if (cross_pf_port)
		df->conntrack->incoming_flow_offloaded_flag.pf1 = true;
	else
		df->conntrack->incoming_flow_offloaded_flag.pf0 = true;

	// prepare the new ethernet header to replace the IPIP one
	rte_ether_addr_copy(dp_get_neigh_mac(df->nxt_hop), &new_eth_hdr.dst_addr);
	rte_ether_addr_copy(dp_get_mac(df->nxt_hop), &new_eth_hdr.src_addr);
	new_eth_hdr.ether_type = htons(df->l3_type);

	// restore the actual incoming pkt's ipv6 dst addr
	if (dp_get_pkt_mark(m)->flags.is_recirc)
		rte_memcpy(df->tun_info.ul_dst_addr6, df->tun_info.ul_src_addr6, sizeof(df->tun_info.ul_dst_addr6));

	// create flow match patterns
	dp_set_eth_flow_item(&pattern[pattern_cnt++], &eth_spec, htons(df->tun_info.l3_type));

	dp_set_ipv6_dst_flow_item(&pattern[pattern_cnt++], &ipv6_spec, df->tun_info.ul_dst_addr6, df->tun_info.proto_id);

	if (df->l3_type == RTE_ETHER_TYPE_IPV6) {
		dp_set_ipv6_dst_flow_item(&pattern[pattern_cnt++], &l3_spec.ipv6, df->dst.dst_addr6, df->l4_type);
	} else {
		// if this flow is the returned vip-natted flow, inner ipv4 addr shall be the VIP (NAT addr)
		actual_ol_ipv4_addr = df->flags.nat == DP_NAT_CHG_DST_IP
								? df->nat_addr
								: df->dst.dst_addr;
		dp_set_ipv4_dst_flow_item(&pattern[pattern_cnt++], &l3_spec.ipv4, actual_ol_ipv4_addr, df->l4_type);
	}

	if (DP_FAILED(dp_set_l4_flow_item(&pattern[pattern_cnt++], &l4_spec, df)))
		return DP_ERROR;

	dp_set_end_flow_item(&pattern[pattern_cnt++]);

	// create special actions
	if ((!cross_pf_port) && dp_port_get(m->port)->captured) {
		agectx_special = allocate_agectx();
		if (!agectx_special)
			return DP_ERROR;

		attr = &dp_flow_attr_transfer_multi_stage;

		age_action_special = &special_moni_action[special_moni_action_cnt++];
		dp_set_flow_age_action(age_action_special, &flow_age_special, df->conntrack->timeout_value, agectx_special);
		
		dp_set_jump_group_action(&special_moni_action[special_moni_action_cnt++], &jump_action, DP_RTE_FLOW_MONITORING_GROUP);
		
		dp_set_end_action(&special_moni_action[special_moni_action_cnt++]);
		// struct rte_flow *sp_flow;

		if (DP_FAILED(dp_install_rte_flow_with_indirect(m->port, &dp_flow_pf_attr_transfer_special,
													pattern, special_moni_action, age_action_special, df, agectx_special))) {
			dp_destroy_rte_flow_agectx(agectx_special);
			return DP_ERROR;
		}

		DPS_LOG_DEBUG("Installed special flow rule on PF", DP_LOG_PORTID(m->port));
	}


	// remove the IPIP header and replace it with a standard Ethernet header
	dp_set_raw_decap_action(&actions[action_cnt++], &raw_decap, NULL, DP_IPIP_ENCAP_HEADER_SIZE);
	dp_set_raw_encap_action(&actions[action_cnt++], &raw_encap, (uint8_t *)&new_eth_hdr, sizeof(new_eth_hdr));

	// replace dst ip if VIP/NAT enabled
	if (df->flags.nat == DP_NAT_CHG_DST_IP) {
		dp_set_ipv4_set_dst_action(&actions[action_cnt++], &set_ipv4, df->dst.dst_addr);
		// also replace dst port if NAT enabled
		if (df->conntrack->nf_info.nat_type == DP_FLOW_NAT_TYPE_NETWORK_LOCAL)
			dp_set_trans_proto_set_dst_action(&actions[action_cnt++], &set_tp,
											  htons(df->conntrack->flow_key[DP_FLOW_DIR_ORG].src.port_src));
	}

	// make flow aging work
	agectx = allocate_agectx();
	if (!agectx)
		return DP_ERROR;

	age_action = &actions[action_cnt++];
	dp_set_flow_age_action(age_action, &flow_age, df->conntrack->timeout_value, agectx);

	if (cross_pf_port) {
		// move this packet to the right hairpin rx queue of pf, so as to be moved to vf
		port = dp_port_get_vf((uint16_t)df->nxt_hop);
		if (!port) {
			DPS_LOG_ERR("Port not registered in service", DP_LOG_PORTID(df->nxt_hop));
			dp_destroy_rte_flow_agectx(agectx);
			return DP_ERROR;
		}
		// pf's rx hairpin queue for vf starts from index 2. (0: normal rxq, 1: hairpin rxq for another pf.)
		dp_set_redirect_queue_action(&actions[action_cnt++], &redirect_queue,
									 DP_NR_RESERVED_RX_QUEUES - 1 + port->peer_pf_hairpin_tx_rx_queue_offset);
	} else
		dp_set_send_to_port_action(&actions[action_cnt++], &send_to_port, df->nxt_hop);

	dp_set_end_action(&actions[action_cnt++]);

	if (DP_FAILED(dp_install_rte_flow_with_indirect(m->port,
													cross_pf_port? &dp_flow_pf_attr_ingress : attr,
													pattern, actions,
													age_action, df, agectx))
	) {
		dp_destroy_rte_flow_agectx(agectx);
		return DP_ERROR;
	}

	if (cross_pf_port)
		DPS_LOG_DEBUG("Installed flow rules to handle hairpin pkts on both PF and VF", DP_LOG_PORTID(m->port), DP_LOG_PORTID(df->nxt_hop));
	else
		DPS_LOG_DEBUG("Installed normal decap flow rule on PF", DP_LOG_PORTID(m->port));
	
	return DP_OK;
}

static __rte_always_inline int dp_offload_handle_local_traffic(struct rte_mbuf *m, struct dp_flow *df)
{
	// match local traffic packets
	struct rte_flow_item_eth eth_spec; // #1
	union dp_flow_item_l3 l3_spec;     // #2
	union dp_flow_item_l4 l4_spec;     // #3
	struct rte_flow_item pattern[4];   // + end
	int pattern_cnt = 0;

	// action steps to send to the right VM
	struct rte_flow_action_set_mac set_dst_mac;  // #1
	struct rte_flow_action_set_mac set_src_mac;  // #2
	struct rte_flow_action_set_ipv4 set_ipv4;    // #3 (optional)
	struct rte_flow_action_age flow_age;         // #4
	struct rte_flow_action_port_id send_to_port; // #5
	struct rte_flow_action actions[6];           // + end
	int action_cnt = 0;

	// misc variables needed to create the flow
	struct flow_age_ctx *agectx;
	struct rte_flow_action *age_action;
	rte_be32_t actual_ol_ipv4_dst_addr;

	// create local flow match pattern
	dp_set_eth_flow_item(&pattern[pattern_cnt++], &eth_spec, htons(df->l3_type));

	if (df->l3_type == RTE_ETHER_TYPE_IPV6) {
		dp_set_ipv6_dst_flow_item(&pattern[pattern_cnt++], &l3_spec.ipv6, df->dst.dst_addr6, df->l4_type);
	} else {
		// if this flow is the returned vip-natted flow, inner ipv4 addr shall be the VIP (NAT addr)
		actual_ol_ipv4_dst_addr = df->flags.nat == DP_NAT_CHG_DST_IP
									? df->nat_addr
									: df->dst.dst_addr;
		dp_set_ipv4_src_dst_flow_item(&pattern[pattern_cnt++],
									  &l3_spec.ipv4,
									  df->src.src_addr,
									  actual_ol_ipv4_dst_addr,
									  df->l4_type);
	}

	if (DP_FAILED(dp_set_l4_flow_item(&pattern[pattern_cnt++], &l4_spec, df)))
		return DP_ERROR;

	dp_set_end_flow_item(&pattern[pattern_cnt++]);

	// set proper ethernet addresses
	dp_set_dst_mac_set_action(&actions[action_cnt++], &set_dst_mac, dp_get_neigh_mac(df->nxt_hop));
	dp_set_src_mac_set_action(&actions[action_cnt++], &set_src_mac, dp_get_mac(df->nxt_hop));

	// replace IPv4 address in overlay if VIP/NAT enabled
	if (df->flags.nat == DP_NAT_CHG_DST_IP) {
		dp_set_ipv4_set_dst_action(&actions[action_cnt++], &set_ipv4, df->dst.dst_addr);
	} else if (df->flags.nat == DP_NAT_CHG_SRC_IP) {
		// there should be more strict condition to only apply to VIP nat pkt
		dp_set_ipv4_set_src_action(&actions[action_cnt++], &set_ipv4, df->nat_addr);
	}

	// make flow aging work
	agectx = allocate_agectx();
	if (!agectx)
		return DP_ERROR;

	age_action = &actions[action_cnt++];
	dp_set_flow_age_action(age_action, &flow_age, df->conntrack->timeout_value, agectx);

	// send to the right port
	dp_set_send_to_port_action(&actions[action_cnt++], &send_to_port, df->nxt_hop);

	dp_set_end_action(&actions[action_cnt++]);

	// TODO: this attribute has not been tested with DPDK 22.11,
	// so maybe 'dp_flow_attr_transfer' should be ifdef'd too
	if (DP_FAILED(dp_install_rte_flow_with_indirect(m->port, &dp_flow_attr_transfer_single_stage,
													pattern, actions,
													age_action, df, agectx))
	) {
		dp_destroy_rte_flow_agectx(agectx);
		return DP_ERROR;
	}

	DPS_LOG_DEBUG("Installed local flow rule", DP_LOG_PORTID(m->port));
	return DP_OK;
}

static __rte_always_inline int dp_offload_handle_in_network_traffic(struct rte_mbuf *m, struct dp_flow *df)
{
	// match in-network underlay packets
	struct rte_flow_item_eth eth_spec;   // #1
	struct rte_flow_item_ipv6 ipv6_spec; // #2
	union dp_flow_item_l3 l3_spec;       // #3
	union dp_flow_item_l4 l4_spec;       // #4
	struct rte_flow_item pattern[5];     // + end
	int pattern_cnt = 0;

	// action steps to send to the right underlay target
	struct rte_flow_action_set_mac set_src_mac;  // #1
	struct rte_flow_action_set_mac set_dst_mac;  // #2
	struct rte_flow_action_set_ipv6 set_ipv6;    // #3
	struct rte_flow_action_age flow_age;         // #4
	struct rte_flow_action_queue redirect_queue; // #5
	struct rte_flow_action actions[6];           // + end
	int action_cnt = 0;

	// misc variables needed to create the flow
	struct flow_age_ctx *agectx;

	// create match pattern based on dp_flow
	dp_set_eth_flow_item(&pattern[pattern_cnt++], &eth_spec, htons(df->tun_info.l3_type));

	// trick: ul_src_addr6 is actually the original dst ipv6 of bouncing pkt
	dp_set_ipv6_dst_flow_item(&pattern[pattern_cnt++], &ipv6_spec, df->tun_info.ul_src_addr6, df->tun_info.proto_id);

	// inner packet matching (L3+L4)
	if (df->l3_type == RTE_ETHER_TYPE_IPV6)
		dp_set_ipv6_dst_flow_item(&pattern[pattern_cnt++], &l3_spec.ipv6, df->dst.dst_addr6, df->l4_type);
	else
		dp_set_ipv4_dst_flow_item(&pattern[pattern_cnt++], &l3_spec.ipv4, df->dst.dst_addr, df->l4_type);

	if (DP_FAILED(dp_set_l4_flow_item(&pattern[pattern_cnt++], &l4_spec, df)))
		return DP_ERROR;

	dp_set_end_flow_item(&pattern[pattern_cnt++]);


	// set proper ethernet addresses
	// in network traffic has to be set via the other pf port via hairpin
	df->nxt_hop = m->port == dp_port_get_pf0_id() ? dp_port_get_pf1_id() : m->port;
	dp_set_src_mac_set_action(&actions[action_cnt++], &set_src_mac, dp_get_mac(df->nxt_hop));
	dp_set_dst_mac_set_action(&actions[action_cnt++], &set_dst_mac, dp_get_neigh_mac(df->nxt_hop));

	// set the right underlay address
	dp_set_ipv6_set_dst_action(&actions[action_cnt++], &set_ipv6, df->tun_info.ul_dst_addr6);

	// make flow aging work
	agectx = allocate_agectx();
	if (!agectx)
		return DP_ERROR;

	dp_set_flow_age_action(&actions[action_cnt++],
						   &flow_age,
#ifdef ENABLE_PYTEST
						   dp_conf_get_flow_timeout(),
#else
						   DP_FLOW_DEFAULT_TIMEOUT,
#endif
						   agectx);

	// move this packet to the right hairpin rx queue of pf, so as to be moved to vf
	// queue_index is the 1st hairpin rx queue of pf, which is paired with another hairpin tx queue of pf
	dp_set_redirect_queue_action(&actions[action_cnt++], &redirect_queue, DP_NR_STD_RX_QUEUES);

	dp_set_end_action(&actions[action_cnt++]);

	// bouncing back rule's expiration is taken care of by the rte flow rule expiration mechanism;
	// no need to perform query to perform checking on expiration status, thus an indirect action is not needed

	if (DP_FAILED(dp_install_rte_flow_with_age(m->port, &dp_flow_pf_attr_ingress, pattern, actions, df->conntrack, agectx))) {
		dp_destroy_rte_flow_agectx(agectx);
		return DP_ERROR;
	}

	DPS_LOG_DEBUG("Installed in-network decap flow rule on PF", DP_LOG_PORTID(m->port));
	return DP_OK;
}

int dp_offload_handler(struct rte_mbuf *m, struct dp_flow *df)
{
	int ret;

	// TODO(plague): think about using enum for flow_type
	if (df->flags.flow_type == DP_FLOW_TYPE_LOCAL) {
		ret = dp_offload_handle_local_traffic(m, df);
		if (DP_FAILED(ret))
			DPS_LOG_ERR("Failed to install local flow rule", DP_LOG_PORTID(m->port), DP_LOG_RET(ret));
	} else if (df->flags.flow_type == DP_FLOW_TYPE_INCOMING) {
		ret = dp_offload_handle_tunnel_decap_traffic(m, df);
		if (DP_FAILED(ret))
			DPS_LOG_ERR("Failed to install decap flow rule", DP_LOG_PORTID(m->port), DP_LOG_RET(ret));
	} else if (df->flags.flow_type == DP_FLOW_TYPE_OUTGOING) {
		if (df->conntrack->nf_info.nat_type == DP_FLOW_NAT_TYPE_NETWORK_NEIGH
			|| df->conntrack->nf_info.nat_type == DP_FLOW_LB_TYPE_FORWARD
		) {
			ret = dp_offload_handle_in_network_traffic(m, df);
			if (DP_FAILED(ret))
				DPS_LOG_ERR("Failed to install in-network flow rule", DP_LOG_PORTID(m->port), DP_LOG_RET(ret));
		} else {
			ret = dp_offload_handle_tunnel_encap_traffic(m, df);
			if (DP_FAILED(ret))
				DPS_LOG_ERR("Failed to install encap flow rule", DP_LOG_PORTID(m->port), DP_LOG_RET(ret));
		}
	} else {
		DPS_LOG_ERR("Invalid flow type to offload", DP_LOG_PORTID(m->port), DP_LOG_VALUE(df->flags.flow_type));
		ret = DP_ERROR;
	}
	return ret;
}
