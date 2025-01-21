// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

/***********************************************************************/
/*                        DO NOT EDIT THIS FILE                        */
/*                                                                     */
/* This file has been generated by dp_conf_generate.py                 */
/* Please edit dp_conf.json and re-run the script to update this file. */
/***********************************************************************/

const char *dp_conf_get_eal_file_prefix(void);
bool dp_conf_is_showing_drops(void);
bool dp_conf_is_stop_mode(void);

enum dp_conf_runmode {
	DP_CONF_RUNMODE_NORMAL, /**< Start normally */
	DP_CONF_RUNMODE_EXIT,   /**< End succesfully (e.g. for --help etc.) */
	DP_CONF_RUNMODE_ERROR,  /**< Error parsing arguments */
};

enum dp_conf_runmode dp_conf_parse_args(int argc, char **argv);
