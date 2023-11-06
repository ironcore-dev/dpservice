#include "rte_flow/dp_rte_flow_capture.h"

#include "dp_error.h"
#include "dp_log.h"
#include "rte_flow/dp_rte_flow_helpers.h"
#include "dp_conf.h"
#include "monitoring/dp_monitoring.h"

#define DP_RTE_FLOW_CAPTURE_PKT_HDR_SIZE (sizeof(struct rte_ether_hdr) \
											 + sizeof(struct rte_ipv6_hdr) \
											 + sizeof(struct rte_udp_hdr))

// this attribute value is used to install a flow rule in the default group of a VF to switch between the capturing group and vnet group
static const struct rte_flow_attr dp_flow_attr_default_jump_ingress = {
	.group = DP_RTE_FLOW_DEFAULT_GROUP,
	.priority = 0,
	.ingress = 0,
	.egress = 0,
	.transfer = 1,
};

// this attribute value is used to install the flow capturing rule into the capturing group
// transfer flag is set to allow the port action
static const struct rte_flow_attr dp_flow_attr_default_capture_ingress = {
	.group = DP_RTE_FLOW_CAPTURE_GROUP,
	.priority = 0,
	.ingress = 0,
	.egress = 0,
	.transfer = 1,
};

int dp_install_jump_rule_in_default_group(uint16_t port_id, uint32_t dst_group)
{
	struct rte_flow_item pattern[2]; // first is a NULL ethernet header matching, second is the end
	int pattern_cnt = 0;

	// jump action from default group to capturing group
	struct rte_flow_action_jump jump_action;	// #1
	struct rte_flow_action action[2];			// + end
	int action_cnt = 0;

	struct rte_flow *flow;
	struct dp_port *port;

	port = dp_get_port(port_id);
	if (!port)
		return DP_ERROR;

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

void dp_configure_pkt_capture_action(uint8_t *encaped_mirror_hdr,
										struct rte_flow_action_raw_encap *encap_action,
										struct rte_flow_action_port_id *port_id_action,
										struct rte_flow_action *sub_action)
{
	struct rte_ether_hdr *encap_eth_hdr = (struct rte_ether_hdr *)encaped_mirror_hdr;
	struct rte_ipv6_hdr *new_ipv6_hdr = (struct rte_ipv6_hdr *)(&encaped_mirror_hdr[sizeof(struct rte_ether_hdr)]);
	struct rte_udp_hdr *udp_hdr = (struct rte_udp_hdr *)(&encaped_mirror_hdr[sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv6_hdr)]);
	int sub_action_cnt = 0;
	uint16_t outgoing_port_id = dp_get_pf0()->port_id;
	const struct dp_capture_hdr_config *capture_hdr_config = dp_get_capture_hdr_config();

	rte_ether_addr_copy(dp_get_neigh_mac(outgoing_port_id), &encap_eth_hdr->dst_addr);
	rte_ether_addr_copy(dp_get_mac(outgoing_port_id), &encap_eth_hdr->src_addr);
	encap_eth_hdr->ether_type = htons(RTE_ETHER_TYPE_IPV6);

	rte_memcpy(new_ipv6_hdr->src_addr, dp_conf_get_underlay_ip(), sizeof(new_ipv6_hdr->src_addr));
	rte_memcpy(new_ipv6_hdr->dst_addr, capture_hdr_config->capture_node_ipv6_addr, sizeof(new_ipv6_hdr->dst_addr));
	new_ipv6_hdr->vtc_flow = htonl(DP_IP6_VTC_FLOW);
	new_ipv6_hdr->payload_len = 0;
	new_ipv6_hdr->proto = DP_IP_PROTO_UDP;
	new_ipv6_hdr->hop_limits = DP_IP6_HOP_LIMIT;

	udp_hdr->dst_port = htons(capture_hdr_config->capture_udp_dst_port);
	udp_hdr->src_port = htons(capture_hdr_config->capture_udp_src_port);
	udp_hdr->dgram_cksum = 0;

	dp_set_raw_encap_action(&sub_action[sub_action_cnt++], encap_action, encaped_mirror_hdr, DP_RTE_FLOW_CAPTURE_PKT_HDR_SIZE);
	dp_set_send_to_port_action(&sub_action[sub_action_cnt++], port_id_action, outgoing_port_id); // must be a pf port here
	dp_set_end_action(&sub_action[sub_action_cnt++]);
}


static int dp_install_default_rule_in_capture_group(uint16_t port_id, bool capture_on)
{

	struct rte_flow_item pattern[2]; // first is a NULL ethernet header matching, second is the end
	int pattern_cnt = 0;

	struct rte_flow_action_sample sample_action;	// #1
	struct rte_flow_action_jump jump_action;		// #2
	struct rte_flow_action action[3];				// + end
	int action_cnt = 0;

	struct rte_flow_action_raw_encap encap_action;	// #1
	struct rte_flow_action_port_id port_id_action;	// #2
	struct rte_flow_action sub_action[3];			// + end

	struct rte_flow *flow;
	struct dp_port *port;
	uint8_t raw_encap_hdr[DP_RTE_FLOW_CAPTURE_PKT_HDR_SIZE];

	port = dp_get_port(port_id);
	if (!port)
		return DP_ERROR;

	// all ethernet packets
	dp_set_eth_match_all_item(&pattern[pattern_cnt++]);
	dp_set_end_flow_item(&pattern[pattern_cnt++]);

	// create actions
	// create sampling action
	if (capture_on) {
		dp_configure_pkt_capture_action(raw_encap_hdr, &encap_action, &port_id_action, sub_action);
		dp_set_sample_action(&action[action_cnt++], &sample_action, 1, sub_action); // sampling with a ratio less than 1 is not allowed in the eSwitch domain
	}

	// create jump group action
	dp_set_jump_group_action(&action[action_cnt++], &jump_action, DP_RTE_FLOW_VNET_GROUP); // jump to group DP_RTE_FLOW_VNET_GROUP

	// end actions
	dp_set_end_action(&action[action_cnt++]);

	// validate and install flow rule
	flow = dp_install_rte_flow(port_id, &dp_flow_attr_default_capture_ingress, pattern, action);
	if (!flow) {
		DPS_LOG_WARNING("Failed to install default monitoring flow rule", DP_LOG_PORTID(port_id));
		return DP_ERROR;
	}

	port->default_capture_flow = flow;

	DPS_LOG_DEBUG("Installed the default monitoring flow rule", DP_LOG_PORTID(port_id));
	return DP_OK;
}


int dp_destroy_default_flow(struct dp_port *port)
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

static int dp_install_pf_default_flow(struct dp_port *port, bool capture_on)
{
	int ret;

	ret = dp_install_default_rule_in_capture_group(port->port_id, capture_on);
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

	ret = dp_install_default_rule_in_capture_group(port->port_id, true);
	if (DP_FAILED(ret)) {
		DPS_LOG_WARNING("Failed to install default capture flow", DP_LOG_PORTID(port->port_id), DP_LOG_RET(ret));
		return DP_ERROR;
	}

	return DP_OK;
}

int dp_enable_pkt_capture(struct dp_port *port)
{
	if (!port || !port->allocated)
		return DP_GRPC_ERR_NO_VM;

	if (port->captured)
		return DP_GRPC_ERR_ALREADY_ACTIVE;

	if (DP_FAILED(dp_destroy_default_flow(port)))
		return DP_GRPC_ERR_RTE_RULE_DEL;

	switch (port->port_type) {
	case DP_PORT_PF:
		if (DP_FAILED(dp_install_pf_default_flow(port, true)))
			return DP_GRPC_ERR_RTE_RULE_ADD;
		break;
	case DP_PORT_VF:
		if (DP_FAILED(dp_install_vf_default_jump_flow(port, DP_RTE_FLOW_CAPTURE_GROUP)))
			return DP_GRPC_ERR_RTE_RULE_ADD;
		// rollback flow rules if failed on the second one for VF.
		if (DP_FAILED(dp_install_vf_default_capture_flow(port))) {
			if (DP_FAILED(dp_destroy_default_flow(port))) {
				DPS_LOG_ERR("Failed to recover from turning capturing on by destroying previously installed default rule", DP_LOG_PORTID(port->port_id));
				return DP_GRPC_ERR_ROLLBACK;
			}
			if (DP_FAILED(dp_install_vf_default_jump_flow(port, DP_RTE_FLOW_VNET_GROUP))) {
				DPS_LOG_ERR("Failed to recover from turning capturing on by installing default jump rule to the vnet group", DP_LOG_PORTID(port->port_id));
				return DP_GRPC_ERR_ROLLBACK;
			}
			return DP_GRPC_ERR_RTE_RULE_ADD;
		}
		break;
	}

	port->captured = true;
	return DP_GRPC_OK;
}

int dp_disable_pkt_capture(struct dp_port *port)
{
	if (!port || !port->allocated)
		return DP_GRPC_ERR_NO_VM;

	if (!port->captured)
		return DP_GRPC_ERR_NOT_ACTIVE;

	if (DP_FAILED(dp_destroy_default_flow(port)))
		return DP_GRPC_ERR_RTE_RULE_DEL;

	switch (port->port_type) {
	case DP_PORT_PF:
		if (DP_FAILED(dp_install_pf_default_flow(port, false)))
			return DP_GRPC_ERR_RTE_RULE_ADD;
		break;
	case DP_PORT_VF:
		if (DP_FAILED(dp_install_vf_default_jump_flow(port, DP_RTE_FLOW_VNET_GROUP))) {
			// rollback does not make sense here, but rather to report the error. because the default operation should be without capturing.
			DPS_LOG_ERR("Failed to turn capturing off by installing default jump rule to the vnet group on vf", DP_LOG_PORTID(port->port_id));
			return DP_GRPC_ERR_RTE_RULE_ADD;
		}

		break;
	}

	port->captured = false;
	return DP_OK;
}

int dp_disable_pkt_capture_on_all_ifaces(void)
{
	struct dp_ports *ports = dp_get_ports();
	int count = 0;
	int ret;

	DP_FOREACH_PORT(ports, port) {
		if (port->allocated && port->captured) {
			ret = dp_enable_pkt_capture(port);
			if (DP_FAILED(ret))
				return ret;
			count++;
		}
	}
	return count;
}
