#include "dp_port.h"

#include "rte_flow/dp_rte_async_flow.h"
#include "rte_flow/dp_rte_async_flow_template.h"
#include "rte_flow/dp_rte_flow_helpers.h"

static uint8_t pf_pattern_action_template_counter = 0;


static int dp_create_pf_default_async_rule_templates(uint16_t main_eswitch_port_id) {

	struct rte_flow_item pattern[4];
	int pattern_cnt = 0;

	struct rte_flow_action action[2];
	struct rte_flow_action action_mask[2];
	int action_cnt = 0;
	int action_mask_cnt = 0;

	struct rte_flow_pattern_template_attr pattern_template_attr = default_pattern_template_attr;
	struct rte_flow_actions_template_attr action_template_attr = default_action_template_attr;
	int ret;

	struct dp_port* port = dp_get_port_by_id(main_eswitch_port_id);

	// create match pattern template: IP in IPv6 tunnel packets by only matching the proto field in ipv6 header
	dp_set_represented_port_item(&pattern[pattern_cnt++], NULL, 0, DP_SET_FLOW_ITEM_WITH_MASK);
	dp_set_eth_flow_item(&pattern[pattern_cnt++], NULL, 0, DP_SET_FLOW_ITEM_WITH_MASK);
	dp_set_ipv6_flow_item(&pattern[pattern_cnt++], NULL, 0, DP_SET_FLOW_ITEM_WITH_MASK);
	dp_set_end_flow_item(&pattern[pattern_cnt++]);

	ret = dp_rte_async_create_pattern_template(port->port_id, pattern, &pattern_template_attr, &(port->async_templates.pattern_templates[DP_ASYNC_RULE_TYPE_DEFAULT_ISOLATION]));
	if (DP_FAILED(ret))
		return DP_ERROR;

	// create flow action: allow packets to enter dp-service packet queue
	dp_set_redirect_queue_action(&action[action_cnt++], NULL, 0);
	dp_set_end_action(&action[action_cnt++]);

	dp_set_redirect_queue_action(&action_mask[action_mask_cnt++], NULL, 0);
	dp_set_end_action(&action_mask[action_mask_cnt++]);

	ret = dp_rte_async_create_actions_template(0, action, action_mask, &action_template_attr, &(port->async_templates.action_templates[DP_ASYNC_RULE_TYPE_DEFAULT_ISOLATION]));
	if (DP_FAILED(ret))
		return DP_ERROR;

	return DP_OK;
}

// only call this on pf0
int dp_create_pf_async_rte_rule_templates(uint16_t main_eswitch_port_id) {

	DPS_LOG_INFO("Installing async rule templates", DP_LOG_PORTID(main_eswitch_port_id));

	if (DP_FAILED(dp_create_pf_default_async_rule_templates(main_eswitch_port_id))) {
		DPS_LOG_ERR("Failed to create pf async rte rule templates", DP_LOG_PORTID(main_eswitch_port_id));
		return DP_ERROR;
	}
	pf_pattern_action_template_counter ++;

	// add more template pattern/action combinations in the future

	if (DP_FAILED(dp_rte_async_create_template_tables(main_eswitch_port_id, pf_pattern_action_template_counter))) {
		DPS_LOG_ERR("Failed to create pf async rte rule template table", DP_LOG_PORTID(main_eswitch_port_id));
		return DP_ERROR;
	}

	return DP_OK;
}
