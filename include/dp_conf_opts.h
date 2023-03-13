/***********************************************************************/
/*                        DO NOT EDIT THIS FILE                        */
/*                                                                     */
/* This file has been generated by dp_conf_generate.py                 */
/* Please edit dp_conf.json and re-run the script to update this file. */
/***********************************************************************/

enum dp_conf_overlay_type {
	DP_CONF_OVERLAY_TYPE_IPIP,
	DP_CONF_OVERLAY_TYPE_GENEVE,
};

enum dp_conf_nic_type {
	DP_CONF_NIC_TYPE_HW,
	DP_CONF_NIC_TYPE_TAP,
};

enum dp_conf_color {
	DP_CONF_COLOR_NEVER,
	DP_CONF_COLOR_ALWAYS,
	DP_CONF_COLOR_AUTO,
};

const char *dp_conf_get_pf0_name();
const char *dp_conf_get_pf1_name();
const char *dp_conf_get_vf_pattern();
const enum dp_conf_overlay_type dp_conf_get_overlay_type();
const int dp_conf_get_dhcp_mtu();
const double dp_conf_get_wcmp_frac();
const enum dp_conf_nic_type dp_conf_get_nic_type();
const bool dp_conf_is_stats_enabled();
const bool dp_conf_is_conntrack_enabled();
const bool dp_conf_is_ipv6_overlay_enabled();
const bool dp_conf_is_offload_enabled();
#ifdef ENABLE_GRAPHTRACE
const int dp_conf_get_graphtrace_level();
#endif
const enum dp_conf_color dp_conf_get_color();
const int dp_conf_get_grpc_port();
#ifdef ENABLE_PYTEST
const int dp_conf_get_flow_timeout();
#endif
