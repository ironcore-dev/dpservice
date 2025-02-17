// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

/***********************************************************************/
/*                        DO NOT EDIT THIS FILE                        */
/*                                                                     */
/* This file has been generated by dp_conf_generate.py                 */
/* Please edit dp_conf.json and re-run the script to update this file. */
/***********************************************************************/

enum dp_conf_output_format {
	DP_CONF_OUTPUT_FORMAT_HUMAN,
	DP_CONF_OUTPUT_FORMAT_TABLE,
	DP_CONF_OUTPUT_FORMAT_CSV,
	DP_CONF_OUTPUT_FORMAT_JSON,
};

enum dp_conf_table {
	DP_CONF_TABLE_LIST,
	DP_CONF_TABLE_CONNTRACK,
	DP_CONF_TABLE_DNAT,
	DP_CONF_TABLE_IFACE,
	DP_CONF_TABLE_LB,
	DP_CONF_TABLE_LB_ID,
	DP_CONF_TABLE_PORTMAP,
	DP_CONF_TABLE_PORTOVERLOAD,
	DP_CONF_TABLE_SNAT,
	DP_CONF_TABLE_VNF,
	DP_CONF_TABLE_VNF_REV,
	DP_CONF_TABLE_VNI,
};

const char *dp_conf_get_eal_file_prefix(void);
enum dp_conf_output_format dp_conf_get_output_format(void);
enum dp_conf_table dp_conf_get_table(void);
int dp_conf_get_numa_socket(void);
bool dp_conf_is_dump(void);

enum dp_conf_runmode {
	DP_CONF_RUNMODE_NORMAL, /**< Start normally */
	DP_CONF_RUNMODE_EXIT,   /**< End succesfully (e.g. for --help etc.) */
	DP_CONF_RUNMODE_ERROR,  /**< Error parsing arguments */
};

enum dp_conf_runmode dp_conf_parse_args(int argc, char **argv);
