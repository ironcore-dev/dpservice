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
