// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <rte_common.h>

#include "dp_error.h"
#include "dp_version.h"
#include "../common/dp_secondary_eal.h"

#include "inspect.h"
#include "inspect_conntrack.h"
#include "inspect_iface.h"
#include "inspect_lb.h"
#include "inspect_nat.h"
#include "inspect_vnf.h"
#include "inspect_vni.h"

// generated definitions for getopt(),
// generated storage variables and
// generated getters for such variables
#include "opts.h"
#include "opts.c"


static void list_tables(enum dp_conf_output_format format)
{
	const char *format_string = NULL;
	bool first = true;

	switch (format) {
	case DP_CONF_OUTPUT_FORMAT_HUMAN:
		printf("Supported tables (-t argument):\n");
		format_string = "  %s\n";
		break;
	case DP_CONF_OUTPUT_FORMAT_TABLE:
	case DP_CONF_OUTPUT_FORMAT_CSV:
		printf("NAME\n");
		format_string = "%s\n";
		break;
	case DP_CONF_OUTPUT_FORMAT_JSON:
		printf("[\n");
		format_string = "\t\"%s\"";
		break;
	}
	// table_choices is from conf.c
	// start at 1 - skip the "list" option
	for (size_t i = 1; i < RTE_DIM(table_choices); ++i) {
		if (format == DP_CONF_OUTPUT_FORMAT_JSON) {
			if (first)
				first = false;
			else
				printf(",\n");
		}
		printf(format_string, table_choices[i]);
	}

	if (format == DP_CONF_OUTPUT_FORMAT_JSON)
		printf("\n]\n");
}

static int dp_inspect_init(enum dp_conf_table selected_table, enum dp_inspect_output_format format, struct dp_inspect_spec *out_spec)
{
	switch (selected_table) {
	case DP_CONF_TABLE_LIST:
		break;
	case DP_CONF_TABLE_CONNTRACK:
		return dp_inspect_init_conntrack(out_spec, format);
	case DP_CONF_TABLE_DNAT:
		return dp_inspect_init_dnat(out_spec, format);
	case DP_CONF_TABLE_IFACE:
		return dp_inspect_init_iface(out_spec, format);
	case DP_CONF_TABLE_LB:
		return dp_inspect_init_lb(out_spec, format);
	case DP_CONF_TABLE_LB_ID:
		return dp_inspect_init_lb_id(out_spec, format);
	case DP_CONF_TABLE_PORTMAP:
		return dp_inspect_init_portmap(out_spec, format);
	case DP_CONF_TABLE_PORTOVERLOAD:
		return dp_inspect_init_portoverload(out_spec, format);
	case DP_CONF_TABLE_SNAT:
		return dp_inspect_init_snat(out_spec, format);
	case DP_CONF_TABLE_VNF:
		return dp_inspect_init_vnf(out_spec, format);
	case DP_CONF_TABLE_VNF_REV:
		return dp_inspect_init_vnf_rev(out_spec, format);
	case DP_CONF_TABLE_VNI:
		return dp_inspect_init_vni(out_spec, format);
	}
	out_spec->table_name = NULL;
	return DP_OK;
}

// unfortunately it's pretty hard to include the opts.h in the right place, thus this conversion
static enum dp_inspect_output_format get_format(enum dp_conf_output_format format)
{
	switch (format) {
	case DP_CONF_OUTPUT_FORMAT_HUMAN:
		return DP_INSPECT_OUTPUT_FORMAT_HUMAN;
	case DP_CONF_OUTPUT_FORMAT_TABLE:
		return DP_INSPECT_OUTPUT_FORMAT_TABLE;
	case DP_CONF_OUTPUT_FORMAT_CSV:
		return DP_INSPECT_OUTPUT_FORMAT_CSV;
	case DP_CONF_OUTPUT_FORMAT_JSON:
		return DP_INSPECT_OUTPUT_FORMAT_JSON;
	}
	return DP_INSPECT_OUTPUT_FORMAT_TABLE;
}


static void dp_argparse_version(void)
{
	printf("DP Service version %s\n", DP_SERVICE_VERSION);
}

int main(int argc, char **argv)
{
	struct dp_inspect_spec spec;
	const char *file_prefix;
	int ret;

	switch (dp_conf_parse_args(argc, argv)) {
	case DP_CONF_RUNMODE_ERROR:
		return EXIT_FAILURE;
	case DP_CONF_RUNMODE_EXIT:
		return EXIT_SUCCESS;
	case DP_CONF_RUNMODE_NORMAL:
		break;
	}

	file_prefix = dp_conf_get_eal_file_prefix();
	if (!*file_prefix)
		file_prefix = getenv("DP_FILE_PREFIX");

	ret = dp_secondary_eal_init(file_prefix);
	if (DP_FAILED(ret)) {
		fprintf(stderr, "Cannot init EAL %s\n", dp_strerror_verbose(ret));
		return EXIT_FAILURE;
	}

	ret = dp_inspect_init(dp_conf_get_table(), get_format(dp_conf_get_output_format()), &spec);
	if (DP_SUCCESS(ret)) {
		if (!spec.table_name)
			list_tables(dp_conf_get_output_format());
		else
			ret = dp_inspect_table(&spec, dp_conf_get_numa_socket(),
								   dp_conf_is_dump() ? DP_INSPECT_DUMP : DP_INSPECT_COUNT,
								   get_format(dp_conf_get_output_format()));
	}

	dp_secondary_eal_cleanup();

	return DP_FAILED(ret) ? EXIT_FAILURE : EXIT_SUCCESS;
}
