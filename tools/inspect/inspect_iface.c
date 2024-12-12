// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#include "inspect_iface.h"

#include <stdio.h>

#include "dp_error.h"
#include "dp_port.h"

#define IFACE_FORMAT_HUMAN "id: %.*s, port: %p(private)\n"
#define IFACE_FORMAT_TABLE "%-36.*s  %p(private)\n"
#define IFACE_FORMAT_CSV "%.*s,%p\n"
#define IFACE_FORMAT_JSON "{ \"id\": \"%.*s\", \"port\": \"%p (private)\" }"

#define IFACE_HEADER_HUMAN NULL
#define IFACE_HEADER_TABLE "ID                                    PORT\n"
#define IFACE_HEADER_CSV "ID,PORT\n"
#define IFACE_HEADER_JSON NULL

static const char *iface_format_str = IFACE_FORMAT_TABLE;
static const char *iface_header_str = IFACE_HEADER_TABLE;

static void setup_format(enum dp_inspect_output_format format)
{
	switch (format) {
	case DP_INSPECT_OUTPUT_FORMAT_HUMAN:
		iface_header_str = IFACE_HEADER_HUMAN;
		iface_format_str = IFACE_FORMAT_HUMAN;
		break;
	case DP_INSPECT_OUTPUT_FORMAT_TABLE:
		iface_header_str = IFACE_HEADER_TABLE;
		iface_format_str = IFACE_FORMAT_TABLE;
		break;
	case DP_INSPECT_OUTPUT_FORMAT_CSV:
		iface_header_str = IFACE_HEADER_CSV;
		iface_format_str = IFACE_FORMAT_CSV;
		break;
	case DP_INSPECT_OUTPUT_FORMAT_JSON:
		iface_header_str = IFACE_HEADER_JSON;
		iface_format_str = IFACE_FORMAT_JSON;
		break;
	}
}

static void print_header(void)
{
	if (iface_header_str)
		printf(iface_header_str);
}


static int dp_inspect_iface(const void *key, const void *val)
{
	const char *iface_id = key;
	const struct dp_port *iface_port = val;

	printf(iface_format_str,
		DP_IFACE_ID_MAX_LEN, iface_id,
		iface_port
	);
	return DP_OK;
}


const struct dp_inspect_spec dp_inspect_iface_spec = {
	.table_name = "interface_table",
	.dump_func = dp_inspect_iface,
	.setup_format_func = setup_format,
	.print_header_func = print_header,
};
