#ifndef __INCLUDE_DP_RTE_FLOW_CAPTURE_H__
#define __INCLUDE_DP_RTE_FLOW_CAPTURE_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include <rte_flow.h>
#include "dp_port.h"


int dp_install_jump_rule_in_default_group(uint16_t port_id, uint32_t dst_group);

int dp_enable_pkt_capture(struct dp_port *port);
int dp_disable_pkt_capture(struct dp_port *port);

int dp_disable_pkt_capture_on_all_ifaces(void);

int dp_destroy_default_flow(struct dp_port *port);

void dp_configure_pkt_capture_action(uint8_t *encaped_mirror_hdr,
										struct rte_flow_action_raw_encap *encap_action,
										struct rte_flow_action_port_id *port_id_action,
										struct rte_flow_action *sub_action);

#ifdef __cplusplus
}
#endif

#endif
