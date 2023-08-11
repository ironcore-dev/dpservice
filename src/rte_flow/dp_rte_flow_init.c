#include "rte_flow/dp_rte_flow_init.h"

#include "dp_error.h"
#include "dp_log.h"
#include "rte_flow/dp_rte_flow.h"

static const struct rte_flow_attr dp_flow_attr_prio_ingress = {
	.group = 0,
	.priority = 1,
	.ingress = 1,
	.egress = 0,
	.transfer = 0,
};

// TODO(plague): retval checking is not finished here, just bare minimum done
int dp_install_isolated_mode_ipip(int port_id, uint8_t proto_id)
{
	struct rte_flow_item pattern[3];
	int pattern_cnt = 0;
	struct rte_flow_action action[2];
	int action_cnt = 0;

	memset(pattern, 0, sizeof(pattern));
	memset(action, 0, sizeof(action));

	// create flow match patterns -- eth
	struct rte_flow_item_eth eth_spec;

	dp_set_eth_flow_item(&pattern[pattern_cnt++], &eth_spec, htons(RTE_ETHER_TYPE_IPV6));

	// create flow match patterns -- ipv6
	struct rte_flow_item_ipv6 ipv6_spec;

	dp_set_ipv6_flow_item(&pattern[pattern_cnt++], &ipv6_spec, proto_id);

	// create flow match patterns -- end
	dp_set_end_flow_item(&pattern[pattern_cnt++]);

	// create flow action -- queue
	struct rte_flow_action_queue queue_action;

	dp_set_redirect_queue_action(&action[action_cnt++], &queue_action, 0);

	// create flow action -- end
	dp_set_end_action(&action[action_cnt++]);

	if (!dp_install_rte_flow(port_id, &dp_flow_attr_prio_ingress, pattern, action))
		return DP_ERROR;

	DPS_LOG_DEBUG("Installed IPIP isolation flow rule", DP_LOG_PORTID(port_id));
	return DP_OK;
}

#ifdef ENABLE_VIRTSVC
int dp_install_isolated_mode_virtsvc(int port_id, uint8_t proto_id, uint8_t svc_ipv6[16], rte_be16_t svc_port)
{
	struct rte_flow_item pattern[4];
	int pattern_cnt = 0;
	struct rte_flow_action action[2];
	int action_cnt = 0;

	memset(pattern, 0, sizeof(pattern));
	memset(action, 0, sizeof(action));

	// create flow match patterns -- eth
	struct rte_flow_item_eth eth_spec;

	dp_set_eth_flow_item(&pattern[pattern_cnt++], &eth_spec, htons(RTE_ETHER_TYPE_IPV6));

	// create flow match patterns -- ipv6
	struct rte_flow_item_ipv6 ipv6_spec;

	dp_set_ipv6_src_flow_item(&pattern[pattern_cnt++], &ipv6_spec, svc_ipv6, proto_id);

	// create flow match patterns -- L4
	struct rte_flow_item_tcp tcp_spec;
	struct rte_flow_item_udp udp_spec;

	if (proto_id == DP_IP_PROTO_TCP) {
		dp_set_tcp_src_flow_item(&pattern[pattern_cnt++], &tcp_spec, svc_port);
	} else if (proto_id == DP_IP_PROTO_UDP) {
		dp_set_udp_src_flow_item(&pattern[pattern_cnt++], &udp_spec, svc_port);
	} else {
		DPS_LOG_ERR("Invalid virtsvc protocol for isolation", DP_LOG_PROTO(proto_id));
		return DP_ERROR;
	}

	// create flow match patterns -- end
	dp_set_end_flow_item(&pattern[pattern_cnt++]);

	// create flow action -- queue
	struct rte_flow_action_queue queue_action;

	dp_set_redirect_queue_action(&action[action_cnt++], &queue_action, 0);

	// create flow action -- end
	dp_set_end_action(&action[action_cnt++]);

	if (!dp_install_rte_flow(port_id, &dp_flow_attr_prio_ingress, pattern, action))
		return DP_ERROR;

	DPS_LOG_DEBUG("Installed virtsvc isolation flow rule", DP_LOG_PORTID(port_id));
	return DP_OK;
}
#endif
