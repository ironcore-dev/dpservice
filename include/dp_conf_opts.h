// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

/***********************************************************************/
/*                        DO NOT EDIT THIS FILE                        */
/*                                                                     */
/* This file has been generated by dp_conf_generate.py                 */
/* Please edit dp_conf.json and re-run the script to update this file. */
/***********************************************************************/

enum dp_conf_nic_type {
	DP_CONF_NIC_TYPE_MELLANOX,
	DP_CONF_NIC_TYPE_TAP,
	DP_CONF_NIC_TYPE_BLUEFIELD2,
};

enum dp_conf_color {
	DP_CONF_COLOR_NEVER,
	DP_CONF_COLOR_ALWAYS,
	DP_CONF_COLOR_AUTO,
};

enum dp_conf_log_format {
	DP_CONF_LOG_FORMAT_TEXT,
	DP_CONF_LOG_FORMAT_JSON,
};

const char *dp_conf_get_pf0_name(void);
const char *dp_conf_get_pf1_name(void);
const char *dp_conf_get_vf_pattern(void);
int dp_conf_get_dhcp_mtu(void);
int dp_conf_get_wcmp_perc(void);
enum dp_conf_nic_type dp_conf_get_nic_type(void);
bool dp_conf_is_stats_enabled(void);
bool dp_conf_is_conntrack_enabled(void);
bool dp_conf_is_ipv6_overlay_enabled(void);
bool dp_conf_is_offload_enabled(void);
#ifdef ENABLE_PYTEST
int dp_conf_get_graphtrace_loglevel(void);
#endif
enum dp_conf_color dp_conf_get_color(void);
enum dp_conf_log_format dp_conf_get_log_format(void);
int dp_conf_get_grpc_port(void);
#ifdef ENABLE_PYTEST
int dp_conf_get_flow_timeout(void);
#endif
bool dp_conf_is_multiport_eswitch(void);
const char *dp_conf_get_active_lockfile(void);

enum dp_conf_runmode {
	DP_CONF_RUNMODE_NORMAL, /**< Start normally */
	DP_CONF_RUNMODE_EXIT,   /**< End succesfully (e.g. for --help etc.) */
	DP_CONF_RUNMODE_ERROR,  /**< Error parsing arguments */
};

enum dp_conf_runmode dp_conf_parse_args(int argc, char **argv);
