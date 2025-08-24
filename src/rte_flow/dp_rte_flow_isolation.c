// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#include "rte_flow/dp_rte_flow_isolation.h"

#include "dp_error.h"
#include "dp_log.h"
#include "rte_flow/dp_rte_flow_helpers.h"
#include "dp_conf.h"
#include "monitoring/dp_monitoring.h"

static const struct rte_flow_attr dp_flow_attr_prio_ingress = {
	.group = 0,
	.priority = 1,
	.ingress = 1,
	.egress = 0,
	.transfer = 0,
};


int dp_install_isolated_mode(uint16_t port_id)
{
	struct rte_flow_item_eth eth_spec;   // #1
	struct rte_flow_item_ipv6 ipv6_spec; // #2
	struct rte_flow_item pattern[3];     // + end
	int pattern_cnt = 0;
	struct rte_flow_action_queue queue_action; // #1
	struct rte_flow_action action[2];          // + end
	int action_cnt = 0;
	union dp_ipv6 ul_addr6;

	ul_addr6._ul.prefix = dp_conf_get_underlay_ip()->_prefix;
	ul_addr6._ul.type = DP_UNDERLAY_ADDRESS_TYPE;

	// create match pattern: IP in IPv6 tunnel packets
	dp_set_eth_flow_item(&pattern[pattern_cnt++], &eth_spec, htons(RTE_ETHER_TYPE_IPV6));
	dp_set_ipv6_dst_pfx68_flow_item(&pattern[pattern_cnt++], &ipv6_spec, &ul_addr6);
	dp_set_end_flow_item(&pattern[pattern_cnt++]);

	// create flow action: allow packets to enter dp-service packet queue
	dp_set_redirect_queue_action(&action[action_cnt++], &queue_action, 0);
	dp_set_end_action(&action[action_cnt++]);

	if (!dp_install_rte_flow(port_id, &dp_flow_attr_prio_ingress, pattern, action))
		return DP_ERROR;

	DPS_LOG_DEBUG("Installed IPIP isolation flow rule", DP_LOG_PORTID(port_id));
	return DP_OK;
}

