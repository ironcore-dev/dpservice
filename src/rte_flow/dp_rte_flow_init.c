#include "rte_flow/dp_rte_flow_init.h"

#include "dp_error.h"
#include "dp_log.h"
#include "rte_flow/dp_rte_flow_helpers.h"
#include "dp_conf.h"
#include "monitoring/dp_monitoring.h"

#define DP_RTE_FLOW_CAPTURE_PKT_HDR_SIZE (sizeof(struct rte_ether_hdr) \
											 + sizeof(struct rte_ipv6_hdr) \
											 + sizeof(struct rte_udp_hdr))

static const struct rte_flow_attr dp_flow_attr_prio_ingress = {
	.group = 0,
	.priority = 1,
	.ingress = 1,
	.egress = 0,
	.transfer = 0,
};

static const struct rte_flow_attr dp_flow_attr_default_jump_ingress = {
	.group = DP_RTE_FLOW_DEFAULT_GROUP,
	.priority = 1,
#ifdef ENABLE_DPDK_22_11
	.ingress = 0,
#else
	.ingress = 1,
#endif
	.egress = 0,
	.transfer = 1,
};

// it is used to install the flow capturing rule into the monitoring group
// transfer flag is set to allow the port action
static const struct rte_flow_attr dp_flow_attr_default_monitoring_ingress = {
	.group = DP_RTE_FLOW_MONITORING_GROUP,
	.priority = 3,
#ifdef ENABLE_DPDK_22_11
	.ingress = 0,
#else
	.ingress = 1,
#endif
	.egress = 0,
	.transfer = 1,
};

// static const struct rte_flow_attr dp_flow_attr_default_capture_ingress = {
// 	.group = DP_RTE_FLOW_VNET_GROUP,
// 	.priority = 3,
// 	.ingress = 1,
// 	.egress = 0,
// 	.transfer = 0,
// };

int dp_install_isolated_mode_ipip(int port_id, uint8_t proto_id)
{
	struct rte_flow_item_eth eth_spec;   // #1
	struct rte_flow_item_ipv6 ipv6_spec; // #2
	struct rte_flow_item pattern[3];     // + end
	int pattern_cnt = 0;
	struct rte_flow_action_queue queue_action; // #1
	struct rte_flow_action action[2];          // + end
	int action_cnt = 0;

	// create match pattern: IP in IPv6 tunnel packets
	dp_set_eth_flow_item(&pattern[pattern_cnt++], &eth_spec, htons(RTE_ETHER_TYPE_IPV6));
	dp_set_ipv6_flow_item(&pattern[pattern_cnt++], &ipv6_spec, proto_id);
	dp_set_end_flow_item(&pattern[pattern_cnt++]);

	// create flow action: allow packets to enter dp-service packet queue
	dp_set_redirect_queue_action(&action[action_cnt++], &queue_action, 0);
	dp_set_end_action(&action[action_cnt++]);

	if (!dp_install_rte_flow(port_id, &dp_flow_attr_prio_ingress, pattern, action))
		return DP_ERROR;

	DPS_LOG_DEBUG("Installed IPIP isolation flow rule", DP_LOG_PORTID(port_id));
	return DP_OK;
}

// static int dp_install_isolate_captured_flow(int port_id)
// {
// 	struct rte_flow_item_eth eth_spec;   // #1
// 	struct rte_flow_item_ipv6 ipv6_spec; // #2
// 	struct rte_flow_item_udp udp_spec;   // #3
// 	struct rte_flow_item pattern[4];     // + end
// 	int pattern_cnt = 0;

// 	struct rte_flow_action_raw_decap raw_decap;  // #1
// 	struct rte_flow_action_queue queue_action; // #2
// 	struct rte_flow_action action[3];          // + end
// 	int action_cnt = 0;

// 	struct rte_flow *flow;
// 	struct dp_port *port = dp_port_get(port_id);

// 	// set match patterns
// 	dp_set_eth_flow_item(&pattern[pattern_cnt++], &eth_spec, htons(RTE_ETHER_TYPE_IPV6));

// 	dp_set_ipv6_dst_flow_item(&pattern[pattern_cnt++], &ipv6_spec, dp_conf_get_underlay_ip(), DP_IP_PROTO_UDP);

// 	dp_set_udp_dst_flow_item(&pattern[pattern_cnt++], &udp_spec, htons(dp_get_capture_udp_dst_port()));

// 	dp_set_end_flow_item(&pattern[pattern_cnt++]);

// 	// set actions
// 	// dp_set_raw_decap_action(&action[action_cnt++], &raw_decap, NULL, DP_RTE_FLOW_CAPTURE_PKT_HDR_SIZE);
// 	dp_set_redirect_queue_action(&action[action_cnt++], &queue_action, 1);
// 	dp_set_end_action(&action[action_cnt++]);

// 	// validate and install flow rule
// 	flow = dp_install_rte_flow(port_id, &dp_flow_attr_prio_ingress, pattern, action);

// 	if (!flow)
// 		return DP_ERROR;

// 	port->default_capture_pkt_isolation_rule = flow;

// 	return DP_OK;
// }

int dp_install_jump_rule_in_default_group(uint16_t port_id, uint32_t dst_group)
{
	struct rte_flow_item pattern[2]; // first is a NULL ethernet header matching, second is the end
	int pattern_cnt = 0;

	// jump action from default group to monitoring group
	struct rte_flow_action_jump jump_action; // #1
	struct rte_flow_action action[2];	// + end
	int action_cnt = 0;

	struct rte_flow *flow;
	struct dp_port *port = dp_port_get_vf(port_id);

	// all ethernet packets
	dp_set_eth_match_all_item(&pattern[pattern_cnt++]);
	dp_set_end_flow_item(&pattern[pattern_cnt++]);

	// create actions that jump from the default group
	// create jump action
	dp_set_jump_group_action(&action[action_cnt++], &jump_action, dst_group);

	// end actions
	dp_set_end_action(&action[action_cnt++]);

	// validate and install flow rule
	flow = dp_install_rte_flow(port_id, &dp_flow_attr_default_jump_ingress, pattern, action);

	if (!flow)
		return DP_ERROR;

	port->default_jump_flow = flow;

	DPS_LOG_DEBUG("Installed the default jumping flow rule that destinated to group", DP_LOG_PORTID(port_id), DP_LOG_RTE_GROUP(dst_group));
	return DP_OK;
}

void dp_configure_packet_capture_action(uint8_t *encaped_mirror_hdr,
										struct rte_flow_action_raw_encap *encap_action,
										struct rte_flow_action_port_id *port_id_action,
										struct rte_flow_action *sub_action,
										uint32_t install_to_port)
{
	struct rte_ether_hdr *encap_eth_hdr = (struct rte_ether_hdr *)encaped_mirror_hdr;
	struct rte_ipv6_hdr *new_ipv6_hdr = (struct rte_ipv6_hdr*)(&encaped_mirror_hdr[sizeof(struct rte_ether_hdr)]);
	struct rte_udp_hdr *udp_hdr = (struct rte_udp_hdr*)(&encaped_mirror_hdr[sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv6_hdr)]);
	int sub_action_cnt = 0;
	uint32_t dst_port = install_to_port == dp_port_get_pf1_id() ? dp_port_get_pf1_id() : dp_port_get_pf0_id();

	rte_ether_addr_copy(dp_get_neigh_mac(0), &encap_eth_hdr->dst_addr);
	rte_ether_addr_copy(dp_get_mac(0), &encap_eth_hdr->src_addr);
	encap_eth_hdr->ether_type = htons(RTE_ETHER_TYPE_IPV6);

	rte_memcpy(new_ipv6_hdr->src_addr, dp_conf_get_underlay_ip(), sizeof(new_ipv6_hdr->src_addr));
	rte_memcpy(new_ipv6_hdr->dst_addr, dp_get_capture_node_ipv6_addr(), sizeof(new_ipv6_hdr->dst_addr));
	new_ipv6_hdr->vtc_flow = htonl(DP_IP6_VTC_FLOW);
	new_ipv6_hdr->payload_len = 0;
	new_ipv6_hdr->proto = DP_IP_PROTO_UDP; 
	new_ipv6_hdr->hop_limits = DP_IP6_HOP_LIMIT;


	udp_hdr->dst_port = htons(dp_get_capture_udp_dst_port());
	udp_hdr->src_port = htons(dp_get_capture_udp_src_port());
	udp_hdr->dgram_cksum = 0;

	dp_set_raw_encap_action(&sub_action[sub_action_cnt++], encap_action, encaped_mirror_hdr, DP_RTE_FLOW_CAPTURE_PKT_HDR_SIZE);
	dp_set_send_to_port_action(&sub_action[sub_action_cnt++], port_id_action, dst_port); // must be a pf port here
	dp_set_end_action(&sub_action[sub_action_cnt++]);
}


int dp_install_default_rule_in_monitoring_group(uint16_t port_id, bool is_on)
{

	struct rte_flow_item pattern[2]; // first is a NULL ethernet header matching, second is the end
	int pattern_cnt = 0;

	struct rte_flow_action_sample sample_action; // 1
	struct rte_flow_action_jump jump_action;	// 2
	struct rte_flow_action action[3];			// + end
	int action_cnt = 0;

	struct rte_flow_action_raw_encap encap_action; // 1
	struct rte_flow_action_port_id port_id_action; // 2
	struct rte_flow_action sub_action[3];
	int sub_action_cnt = 0;

	struct rte_flow *flow;
	struct dp_port *port = dp_port_get(port_id);
	uint8_t raw_encap_hdr[DP_RTE_FLOW_CAPTURE_PKT_HDR_SIZE];

	// all ethernet packets
	dp_set_eth_match_all_item(&pattern[pattern_cnt++]);
	dp_set_end_flow_item(&pattern[pattern_cnt++]);

	// create actions
	// create sampling action
	if (is_on) {
		dp_configure_packet_capture_action(raw_encap_hdr, &encap_action, &port_id_action, sub_action, port_id);
		dp_set_sample_action(&action[action_cnt++], &sample_action, 1, sub_action); // mirror all packets, without explicite sub sample action
	}

	// create jump group action
	dp_set_jump_group_action(&action[action_cnt++], &jump_action, DP_RTE_FLOW_VNET_GROUP); // jump to group DP_RTE_FLOW_VNET_GROUP

	// end actions
	dp_set_end_action(&action[action_cnt++]);

	// validate and install flow rule
	flow = dp_install_rte_flow(port_id, &dp_flow_attr_default_monitoring_ingress, pattern, action);

	if (!flow) {
		DPS_LOG_DEBUG("Failed to install default monitoring flow rule on port %d \n", DP_LOG_PORTID(port_id));
		return DP_ERROR;
	}
	

	// PF's default flow to enable flow mirroring is this default monitoring flow
	// if (port->port_type == DP_PORT_PF)
	port->default_capture_flow = flow;

	DPS_LOG_DEBUG("Installed the default monitoring flow rule", DP_LOG_PORTID(port_id));
	return DP_OK;
}

// int dp_install_default_capture_rule_in_vnet_group(uint16_t port_id)
// {

// 	struct rte_flow_item pattern[2]; // first is a NULL ethernet header matching, second is the end
// 	int pattern_cnt = 0;

// 	struct rte_flow_action_queue queue_action;	// 1
// 	struct rte_flow_action action[2];		// + end
// 	int action_cnt = 0;

// 	// all ethernet packets
// 	dp_set_eth_match_all_item(&pattern[pattern_cnt++]);
// 	dp_set_end_flow_item(&pattern[pattern_cnt++]);

// 	// create actions
// 	// create flow action -- queue, send to default software handling queue
// 	dp_set_redirect_queue_action(&action[action_cnt++], &queue_action, 0);
// 	// create flow action -- end
// 	dp_set_end_action(&action[action_cnt++]);

// 	if (!dp_install_rte_flow(port_id, &dp_flow_attr_default_capture_ingress, pattern, action))
// 		return DP_ERROR;

// 	DPS_LOG_DEBUG("Installed the default capture flow rule", DP_LOG_PORTID(port_id));
// 	return DP_OK;
// }

// static int dp_change_all_vf_default_jump_rte_flow_group(uint32_t dst_group)
// {
// 	struct dp_ports *ports = get_dp_ports();
// 	struct rte_flow_error error;
// 	int ret;

// 	DP_FOREACH_PORT(ports, port) {
// 		if (port->port_type == DP_PORT_VF && port->allocated) {
// 			if (port->default_flow) {
// 				ret = rte_flow_destroy(port->port_id, port->default_flow, &error);

// 				if (DP_FAILED(ret)) {
// 					DPS_LOG_WARNING("Failed to destroy default flow", DP_LOG_PORTID(port->port_id), DP_LOG_RET(ret));
// 					continue;
// 				}
// 			}

// 			if (DP_FAILED(dp_install_jump_rule_in_default_group(port->port_id, dst_group))) {
// 				DPS_LOG_WARNING("Failed to install default jump flow", DP_LOG_PORTID(port->port_id));
// 				continue;
// 			}
// 		}
// 	}

// 	return DP_OK;
// }

static int dp_destroy_default_flow(struct dp_port *port)
{
	struct rte_flow_error error;
	int ret;

	if (port->default_jump_flow) {
		ret = rte_flow_destroy(port->port_id, port->default_jump_flow, &error);

		if (DP_FAILED(ret)) {
			DPS_LOG_WARNING("Failed to destroy default jump flow", DP_LOG_PORTID(port->port_id), DP_LOG_RET(ret));
			return DP_ERROR;
		}
	}

	if (port->default_capture_flow) {
		ret = rte_flow_destroy(port->port_id, port->default_capture_flow, &error);

		if (DP_FAILED(ret)) {
			DPS_LOG_WARNING("Failed to destroy default capture flow", DP_LOG_PORTID(port->port_id), DP_LOG_RET(ret));
			return DP_ERROR;
		}
	}

	return DP_OK;
}

static int dp_install_pf_default_flow(struct dp_port *port, bool is_on)
{
	int ret;

	ret = dp_install_default_rule_in_monitoring_group(port->port_id, is_on);
	if (DP_FAILED(ret)) {
		DPS_LOG_WARNING("Failed to install default flow", DP_LOG_PORTID(port->port_id), DP_LOG_RET(ret));
		return DP_ERROR;
	}

	return DP_OK;
}

static int dp_install_vf_default_jump_flow(struct dp_port *port, uint32_t dst_group)
{
	int ret;

	ret = dp_install_jump_rule_in_default_group(port->port_id, dst_group);
	if (DP_FAILED(ret)) {
		DPS_LOG_WARNING("Failed to install default jump flow", DP_LOG_PORTID(port->port_id), DP_LOG_RET(ret));
		return DP_ERROR;
	}

	return DP_OK;
}

static int dp_install_vf_default_capture_flow(struct dp_port *port)
{
	int ret;

	ret = dp_install_default_rule_in_monitoring_group(port->port_id, true);
	if (DP_FAILED(ret)) {
		DPS_LOG_WARNING("Failed to install default capture flow", DP_LOG_PORTID(port->port_id), DP_LOG_RET(ret));
		return DP_ERROR;
	}

	return DP_OK;
}

static int dp_turn_on_offload_pkt_capture(struct dp_port *port)
{
	if (!port->allocated || port->captured)
		return DP_OK;
	
	if (DP_FAILED(dp_destroy_default_flow(port)))
		return DP_ERROR;
	
	printf("destroied default flow on port %d \n", port->port_id);

	switch (port->port_type) {
	case DP_PORT_PF:
		if (DP_FAILED(dp_install_pf_default_flow(port, true)))
			return DP_ERROR;
		break;
	case DP_PORT_VF:
		if (DP_FAILED(dp_install_vf_default_jump_flow(port, DP_RTE_FLOW_MONITORING_GROUP)))
			return DP_ERROR;
		// rollback flow rules if failed on the second one for VF.
		if (DP_FAILED(dp_install_vf_default_capture_flow(port))) {
			if (DP_FAILED(dp_destroy_default_flow(port))) {
				DPS_LOG_ERR("Failed to recover from turning capturing on by destroying previously installed default rule", DP_LOG_PORTID(port->port_id));
				return DP_ERROR;
			}
			if (DP_FAILED(dp_install_vf_default_jump_flow(port, DP_RTE_FLOW_VNET_GROUP)))
				DPS_LOG_ERR("Failed to recover from turning capturing on by installing default jump rule to the vnet group", DP_LOG_PORTID(port->port_id));
			return DP_ERROR;
		}
		break;
	}

	port->captured = true;
	return DP_OK;
}

static int dp_turn_off_offload_pkt_capture(struct dp_port *port)
{
	if (!port->allocated || !port->captured)
		return DP_OK;
	
	if (DP_FAILED(dp_destroy_default_flow(port)))
		return DP_ERROR;

	switch (port->port_type) {
	case DP_PORT_PF:
		if (DP_FAILED(dp_install_pf_default_flow(port, false)))
			return DP_ERROR;
		break;
	case DP_PORT_VF:
		if (DP_FAILED(dp_install_vf_default_jump_flow(port, DP_RTE_FLOW_VNET_GROUP)))
			return DP_ERROR;
		break;
	}

	port->captured = false;
	return DP_OK;
}

int dp_turn_on_offload_pkt_capture_on_single_iface(uint16_t port_id)
{
	struct dp_port *port = dp_port_get(port_id);

	return dp_turn_on_offload_pkt_capture(port);
}

int dp_turn_off_offload_pkt_capture_on_single_iface(uint16_t port_id)
{
	struct dp_port *port = dp_port_get(port_id);
	
	return dp_turn_off_offload_pkt_capture(port);
}

int dp_turn_on_offload_pkt_capture_on_all_ifaces(void)
{
	struct dp_ports *ports = get_dp_ports();

	DP_FOREACH_PORT(ports, port) {
		if (DP_FAILED(dp_turn_on_offload_pkt_capture(port)))
			return DP_ERROR;
	}

	return DP_OK;
}

int dp_turn_off_offload_pkt_capture_on_all_ifaces(void)
{
	struct dp_ports *ports = get_dp_ports();
	int count = 0;

	DP_FOREACH_PORT(ports, port) {
		if (port->captured) {
			if (DP_FAILED(dp_turn_off_offload_pkt_capture(port)))
				return DP_ERROR;
			count ++;
		}
	}
	return count;
}

// int dp_pf_remove_capture_pkt_isolation_rule(void)
// {
// 	int ret;
// 	struct dp_port *port;
// 	struct rte_flow_error error;
// 	struct dp_ports *ports = get_dp_ports();
	
// 	DP_FOREACH_PORT(ports, port) {
// 		if (port->port_type == DP_PORT_PF && port->default_capture_pkt_isolation_rule) {
// 			ret = rte_flow_destroy(port->port_id, port->default_jump_flow, &error);
// 			if (DP_FAILED(ret)) {
// 				DPS_LOG_WARNING("Failed to destroy default capture pkt isolation rule", DP_LOG_PORTID(port->port_id), DP_LOG_RET(ret));
// 				return DP_ERROR;
// 			}
// 		}
// 	}
// 	return DP_OK;

// }

// int dp_pf_install_capture_pkt_isolation_rule(void)
// {
// 	struct dp_port *port;
// 	struct rte_flow_error error;
// 	struct dp_ports *ports = get_dp_ports();
	
// 	// default_capture_pkt_isolation_rule is trusted to be null when start_port is called
// 	DP_FOREACH_PORT(ports, port) {
// 		if (port->port_type == DP_PORT_PF && !port->default_capture_pkt_isolation_rule) {
// 			if (DP_FAILED(dp_install_isolate_captured_flow(port->port_id))) {
// 				DPS_LOG_WARNING("Failed to install isolated_captured_flow", DP_LOG_PORTID(port->port_id));
				
// 				//fallback by removing every installed such rule from pfs, nothing can be done if this failed again, restart maybe
// 				dp_pf_remove_capture_pkt_isolation_rule();
// 				return DP_ERROR;
// 			}
// 		}
// 	}

// 	return DP_OK;
// }

#ifdef ENABLE_VIRTSVC
int dp_install_isolated_mode_virtsvc(int port_id, uint8_t proto_id, uint8_t svc_ipv6[16], rte_be16_t svc_port)
{
	struct rte_flow_item_eth eth_spec;   // #1
	struct rte_flow_item_ipv6 ipv6_spec; // #2
	struct rte_flow_item_tcp tcp_spec;   // #3 (choose one)
	struct rte_flow_item_udp udp_spec;   // #3 (choose one)
	struct rte_flow_item pattern[4];     // + end
	int pattern_cnt = 0;
	struct rte_flow_action_queue queue_action; // #1
	struct rte_flow_action actions[2];         // + end
	int action_cnt = 0;

	// create match pattern: IPv6 packets from selected addresses
	dp_set_eth_flow_item(&pattern[pattern_cnt++], &eth_spec, htons(RTE_ETHER_TYPE_IPV6));
	dp_set_ipv6_src_flow_item(&pattern[pattern_cnt++], &ipv6_spec, svc_ipv6, proto_id);
	if (proto_id == DP_IP_PROTO_TCP) {
		dp_set_tcp_src_flow_item(&pattern[pattern_cnt++], &tcp_spec, svc_port);
	} else if (proto_id == DP_IP_PROTO_UDP) {
		dp_set_udp_src_flow_item(&pattern[pattern_cnt++], &udp_spec, svc_port);
	} else {
		DPS_LOG_ERR("Invalid virtsvc protocol for isolation", DP_LOG_PROTO(proto_id));
		return DP_ERROR;
	}
	dp_set_end_flow_item(&pattern[pattern_cnt++]);

	// create flow action: allow packets to enter dp-service packet queue
	dp_set_redirect_queue_action(&actions[action_cnt++], &queue_action, 0);
	dp_set_end_action(&actions[action_cnt++]);

	if (!dp_install_rte_flow(port_id, &dp_flow_attr_prio_ingress, pattern, actions))
		return DP_ERROR;

	DPS_LOG_DEBUG("Installed virtsvc isolation flow rule", DP_LOG_PORTID(port_id));
	return DP_OK;
}
#endif
