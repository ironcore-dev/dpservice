#include "rte_flow/dp_rte_flow_init.h"

#include "dp_error.h"
#include "dp_log.h"
#include "rte_flow/dp_rte_flow.h"


static int create_flow(int port_id,
					   struct rte_flow_attr *attr,
					   struct rte_flow_item *pattern,
					   struct rte_flow_action *action)
{
	int ret;
	struct rte_flow *flow;
	struct rte_flow_error error = {
		.message = "(no stated reason)",
	};

	ret = rte_flow_validate(port_id, attr, pattern, action, &error);
	if (DP_FAILED(ret)) {
		DPS_LOG_ERR("Flow isolation cannot be validated",
					DP_LOG_PORTID(port_id), DP_LOG_FLOW_ERROR(error.message), DP_LOG_RET(ret));
		return ret;
	}

	flow = rte_flow_create(port_id, attr, pattern, action, &error);
	if (!flow) {
		DPS_LOG_ERR("Flow isolation cannot be created",
					DP_LOG_PORTID(port_id), DP_LOG_FLOW_ERROR(error.message), DP_LOG_RET(rte_errno));
		return DP_ERROR;
	}

	return DP_OK;
}

// TODO(plague): retval checking is not finished here, just bare minimum done
int dp_install_isolated_mode_ipip(int port_id, uint8_t proto_id)
{

	// create flow attributes
	struct rte_flow_attr attr;

	create_rte_flow_rule_attr(&attr, 0, 1, 1, 0, 0);

	struct rte_flow_item pattern[3];
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
												htons(RTE_ETHER_TYPE_IPV6));

	// create flow match patterns -- ipv6
	struct rte_flow_item_ipv6 ipv6_spec;
	struct rte_flow_item_ipv6 ipv6_mask;

	pattern_cnt = insert_ipv6_match_pattern(pattern, pattern_cnt,
											&ipv6_spec, &ipv6_mask,
											NULL, 0, NULL, 0,
											proto_id);

	// create flow match patterns -- end
	pattern_cnt = insert_end_match_pattern(pattern, pattern_cnt);

	// create flow action -- queue
	struct rte_flow_action_queue queue_action;

	action_cnt = create_redirect_queue_action(action, action_cnt,
											  &queue_action, 0);

	// create flow action -- end
	action_cnt = create_end_action(action, action_cnt);

	return create_flow(port_id, &attr, pattern, action);
}

#ifdef ENABLE_VIRTSVC
int dp_install_isolated_mode_virtsvc(int port_id, uint8_t proto_id, uint8_t svc_ipv6[16], rte_be16_t svc_port)
{

	// create flow attributes
	struct rte_flow_attr attr;

	create_rte_flow_rule_attr(&attr, 0, 1, 1, 0, 0);

	struct rte_flow_item pattern[4];
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
												htons(RTE_ETHER_TYPE_IPV6));

	// create flow match patterns -- ipv6
	struct rte_flow_item_ipv6 ipv6_spec;
	struct rte_flow_item_ipv6 ipv6_mask;

	pattern_cnt = insert_ipv6_match_pattern(pattern, pattern_cnt,
											&ipv6_spec, &ipv6_mask,
											svc_ipv6, 16, NULL, 0,
											proto_id);

	// create flow match patterns -- L4
	struct rte_flow_item_tcp tcp_spec;
	struct rte_flow_item_tcp tcp_mask;
	struct rte_flow_item_udp udp_spec;
	struct rte_flow_item_udp udp_mask;

	if (proto_id == DP_IP_PROTO_TCP) {
		pattern_cnt = insert_tcp_match_pattern(pattern, pattern_cnt,
											   &tcp_spec, &tcp_mask,
											   svc_port, 0,
											   0);
	} else if (proto_id == DP_IP_PROTO_UDP) {
		pattern_cnt = insert_udp_match_pattern(pattern, pattern_cnt,
											   &udp_spec, &udp_mask,
											   svc_port, 0);
	} else {
		DPS_LOG_ERR("Invalid virtsvc protocol for isolation", DP_LOG_PROTO(proto_id));
		return DP_ERROR;
	}

	// create flow match patterns -- end
	pattern_cnt = insert_end_match_pattern(pattern, pattern_cnt);

	// create flow action -- queue
	struct rte_flow_action_queue queue_action;

	action_cnt = create_redirect_queue_action(action, action_cnt,
											  &queue_action, 0);

	// create flow action -- end
	action_cnt = create_end_action(action, action_cnt);

	return create_flow(port_id, &attr, pattern, action);
}
#endif
