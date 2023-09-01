#ifndef __INCLUDE_DP_RTE_FLOW_INIT_H__
#define __INCLUDE_DP_RTE_FLOW_INIT_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

int dp_install_isolated_mode_ipip(int port_id, uint8_t proto_id);

int dp_install_jump_rule_int_default_group(uint16_t port_id, uint32_t group_id);
int dp_install_default_rule_in_monitoring_group(uint16_t port_id);
int dp_install_default_capture_rule_in_vnet_group(uint16_t port_id);

int dp_change_all_vf_default_jump_rte_flow_group(uint32_t dst_group);

#ifdef ENABLE_VIRTSVC
int dp_install_isolated_mode_virtsvc(int port_id, uint8_t proto_id, uint8_t svc_ipv6[16], uint16_t svc_port);
#endif

#ifdef __cplusplus
}
#endif

#endif
