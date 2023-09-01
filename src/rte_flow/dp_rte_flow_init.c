#include "rte_flow/dp_rte_flow_init.h"

#include "dp_error.h"
#include "dp_log.h"
#include "rte_flow/dp_rte_flow_helpers.h"

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
	.ingress = 1,
	.egress = 0,
	.transfer = 1,
};

static const struct rte_flow_attr dp_flow_attr_default_monitoring_ingress = {
	.group = DP_RTE_FLOW_MONITORING_GROUP,
	.priority = 3,
	.ingress = 1,
	.egress = 0,
	.transfer = 1,
};

static const struct rte_flow_attr dp_flow_attr_default_capture_ingress = {
	.group = DP_RTE_FLOW_VNET_GROUP,
	.priority = 3,
	.ingress = 1,
	.egress = 0,
	.transfer = 0,
};

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

int dp_install_jump_rule_int_default_group(uint16_t port_id, uint32_t dst_group)
{
	struct rte_flow_item pattern[2]; // first is a NULL ethernet header matching, second is the end
	int pattern_cnt = 0;

	// jump action from default group to monitoring group
	struct rte_flow_action_jump jump_action; // #1
	struct rte_flow_action action[2];	// + end
	int action_cnt = 0;

	struct rte_flow *flow;
	struct dp_port *port = dp_port_get_vf(port_id);

	memset(pattern, 0, sizeof(pattern));
	memset(action, 0, sizeof(action));

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

	port->default_flow = flow;

	DPS_LOG_DEBUG("Installed the default jumping flow rule that destinated to group", DP_LOG_PORTID(port_id), DP_LOG_RTE_GROUP(dst_group));
	return DP_OK;
}

int dp_install_default_rule_in_monitoring_group(uint16_t port_id)
{

	struct rte_flow_item pattern[2]; // first is a NULL ethernet header matching, second is the end
	int pattern_cnt = 0;

	struct rte_flow_action_sample sample_action; // 1
	struct rte_flow_action_jump jump_action;	// 2
	struct rte_flow_action action[3];			// + end
	int action_cnt = 0;

	struct rte_flow_action sub_action[1];
	int sub_action_cnt = 0;

	struct rte_flow *flow;

	memset(pattern, 0, sizeof(pattern));
	memset(action, 0, sizeof(action));
	memset(sub_action, 0, sizeof(sub_action));

	// all ethernet packets
	dp_set_eth_match_all_item(&pattern[pattern_cnt++]);
	dp_set_end_flow_item(&pattern[pattern_cnt++]);

	// create actions
	// create sampling action
	dp_set_end_action(&sub_action[sub_action_cnt++]);
	dp_set_sample_action(&action[action_cnt++], &sample_action, 1, sub_action); // mirror all packets, without explicite sub sample action

	// create jump group action
	dp_set_jump_group_action(&action[action_cnt++], &jump_action, DP_RTE_FLOW_VNET_GROUP); // jump to group DP_RTE_FLOW_VNET_GROUP

	// end actions
	dp_set_end_action(&action[action_cnt++]);

	// validate and install flow rule
	flow = dp_install_rte_flow(port_id, &dp_flow_attr_default_monitoring_ingress, pattern, action);

	if (!flow)
		return DP_ERROR;

	DPS_LOG_DEBUG("Installed the default monitoring flow rule", DP_LOG_PORTID(port_id));
	return DP_OK;

}

int dp_install_default_capture_rule_in_vnet_group(uint16_t port_id)
{

	struct rte_flow_item pattern[2]; // first is a NULL ethernet header matching, second is the end
	int pattern_cnt = 0;

	struct rte_flow_action_queue queue_action;	// 1
	struct rte_flow_action action[2];		// + end
	int action_cnt = 0;

	memset(pattern, 0, sizeof(pattern));
	memset(action, 0, sizeof(action));

	// all ethernet packets
	dp_set_eth_match_all_item(&pattern[pattern_cnt++]);
	dp_set_end_flow_item(&pattern[pattern_cnt++]);

	// create actions
	// create flow action -- queue, send to default software handling queue
	dp_set_redirect_queue_action(&action[action_cnt++], &queue_action, 0);
	// create flow action -- end
	dp_set_end_action(&action[action_cnt++]);

	if (!dp_install_rte_flow(port_id, &dp_flow_attr_default_capture_ingress, pattern, action))
		return DP_ERROR;

	DPS_LOG_DEBUG("Installed the default capture flow rule", DP_LOG_PORTID(port_id));
	return DP_OK;
}

int dp_change_all_vf_default_jump_rte_flow_group(uint32_t dst_group)
{
	struct dp_ports *ports = get_dp_ports();
	struct dp_port *port;
	struct rte_flow_error error;
	int ret;

	DP_FOREACH_PORT(ports, port) {
		if (port->port_type == DP_PORT_VF && port->allocated) {
			if (port->default_flow)
				ret = rte_flow_destroy(port->port_id, port->default_flow, &error);

			if (DP_FAILED(ret)) {
				DPS_LOG_ERR("Failed to destroy default flow", DP_LOG_PORTID(port->port_id), DP_LOG_RET(ret));
				return DP_ERROR;
			}

			if (DP_FAILED(dp_install_jump_rule_int_default_group(port->port_id, dst_group))) {
				DPS_LOG_ERR("Failed to install default jump flow", DP_LOG_PORTID(port->port_id));
				return DP_ERROR;
			}
		}
	}

	return DP_OK;
}

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
