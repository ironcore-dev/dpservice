// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#include "inspect_iface.h"

#include <stdio.h>

#include "dp_error.h"
#include "dp_iface.h"

static const char *g_iface_format;

static int dp_inspect_iface(const void *key, const void *val)
{
	const char *iface_id = key;
	const struct dp_port *iface_port = val;

	printf(g_iface_format,
		DP_IFACE_ID_MAX_LEN, iface_id,
		iface_port
	);
	return DP_OK;
}


int dp_inspect_init_iface(struct dp_inspect_spec *out_spec, enum dp_inspect_output_format format)
{
	out_spec->table_name = DP_IFACE_TABLE_NAME;
	out_spec->dump_func = dp_inspect_iface;
	switch (format) {
	case DP_INSPECT_OUTPUT_FORMAT_HUMAN:
		out_spec->header = NULL;
		g_iface_format = "iface_id: %.*s, port: %p(private)\n";
		break;
	case DP_INSPECT_OUTPUT_FORMAT_TABLE:
		out_spec->header = "IFACE_ID                              PORT\n";
		g_iface_format = "%-36.*s  %p(private)\n";
		break;
	case DP_INSPECT_OUTPUT_FORMAT_CSV:
		out_spec->header = "IFACE_ID,PORT\n";
		g_iface_format = "%.*s,%p\n";
		break;
	case DP_INSPECT_OUTPUT_FORMAT_JSON:
		out_spec->header = NULL;
		g_iface_format = "{ \"iface_id\": \"%.*s\", \"port\": \"%p (private)\" }";
		break;
	}
	return DP_OK;
}
