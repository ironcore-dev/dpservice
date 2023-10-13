#ifndef __INCLUDE_DP_RTE_FLOW_INIT_H__
#define __INCLUDE_DP_RTE_FLOW_INIT_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include <rte_flow.h>
#include "dp_port.h"

int dp_install_isolated_mode_ipip(int port_id, uint8_t proto_id);

int dp_install_jump_rule_in_default_group(uint16_t port_id, uint32_t group_id);
int dp_install_default_rule_in_monitoring_group(uint16_t port_id, bool is_on);
int dp_install_default_capture_rule_in_vnet_group(uint16_t port_id);

// int dp_turn_on_offload_pkt_mirror(void);
// int dp_turn_off_offload_pkt_mirror(void);

int dp_turn_on_offload_pkt_capture_on_single_iface(uint16_t port_id);
int dp_turn_off_offload_pkt_capture_on_single_iface(uint16_t port_id);

int dp_turn_on_offload_pkt_capture_on_all_ifaces(void);
int dp_turn_off_offload_pkt_capture_on_all_ifaces(void);

void dp_configure_packet_capture_action(uint8_t *encaped_mirror_hdr,
 										struct rte_flow_action_raw_encap *encap_action,
 										struct rte_flow_action_port_id *port_id_action,
 										struct rte_flow_action *sub_action,
 										uint32_t install_to_port);

#ifdef ENABLE_VIRTSVC
int dp_install_isolated_mode_virtsvc(int port_id, uint8_t proto_id, const uint8_t svc_ipv6[16], uint16_t svc_port);
#endif

#ifdef __cplusplus
}
#endif

#endif
