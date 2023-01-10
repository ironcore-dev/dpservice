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
	struct rte_flow_error error = {0};

	ret = rte_flow_validate(port_id, attr, pattern, action, &error);
	if (DP_FAILED(ret)) {
		DPS_LOG_ERR("Flow isolation cannot be validated on port %d: %s %s", port_id, error.message, dp_strerror(ret));
		return DP_ERROR;
	}

	flow = rte_flow_create(port_id, attr, pattern, action, &error);
	if (!flow) {
		DPS_LOG_ERR("Flow isolation cannot be created on port %d: %s %s", port_id, error.message, dp_strerror(rte_errno));
		return DP_ERROR;
	}

	return DP_OK;
}

// TODO(plague): retval checking is not finished here, just bare minimum done
// TODO(plague): these two look too similar, maybe it can be refactored
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
												rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6));

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

int dp_install_isolated_mode_geneve(int port_id)
{
	struct underlay_conf *u_conf;

	u_conf = get_underlay_conf();

	// create flow attributes
	struct rte_flow_attr attr;

	create_rte_flow_rule_attr(&attr, 0, 0, 1, 0, 0);

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
											NULL, 0,
											u_conf->src_ip6, sizeof(u_conf->src_ip6),
											DP_IP_PROTO_UDP);

	// create flow match patterns -- UDP
	struct rte_flow_item_udp udp_spec;
	struct rte_flow_item_udp udp_mask;

	pattern_cnt = insert_udp_match_pattern(pattern, pattern_cnt,
										   &udp_spec, &udp_mask,
										   0, htons(u_conf->dst_port));

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
