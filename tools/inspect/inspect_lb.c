// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#include "inspect_lb.h"

#include <stdio.h>

#include "dp_error.h"
#include "dp_ipaddr.h"
#include "dp_lb.h"

static const char *g_lb_format;

static int dp_inspect_lb(const void *key, const void *val)
{
	const struct lb_key *lb_key = key;
	const struct lb_value *lb_val = val;

	char ip[INET6_ADDRSTRLEN];

	DP_IPADDR_TO_STR(&lb_key->ip, ip);
	printf(g_lb_format,
		DP_LB_ID_MAX_LEN, lb_val->lb_id,
		lb_key->vni,
		ip
	);
	return DP_OK;
}

static int dp_inspect_lb_id(const void *key, const void *val)
{
	const char *lb_id = key;
	const struct lb_key *lb_key = val;

	char ip[INET6_ADDRSTRLEN];

	DP_IPADDR_TO_STR(&lb_key->ip, ip);
	printf(g_lb_format,
		DP_LB_ID_MAX_LEN, lb_id,
		lb_key->vni,
		ip
	);
	return DP_OK;
}


static void setup_format(struct dp_inspect_spec *out_spec, enum dp_inspect_output_format format)
{
	switch (format) {
	case DP_INSPECT_OUTPUT_FORMAT_HUMAN:
		out_spec->header = NULL;
		g_lb_format = "lb_id: %.*s, vni: %3u, ip: %15s\n";
		break;
	case DP_INSPECT_OUTPUT_FORMAT_TABLE:
		out_spec->header = "LB_ID                                 VNI  IP\n";
		g_lb_format = "%-36.*s  %3u  %s\n";
		break;
	case DP_INSPECT_OUTPUT_FORMAT_CSV:
		out_spec->header = "LB_ID,VNI,IP\n";
		g_lb_format = "%.*s,%u,%s\n";
		break;
	case DP_INSPECT_OUTPUT_FORMAT_JSON:
		out_spec->header = NULL;
		g_lb_format = "{ \"lb_id\": \"%.*s\", \"vni\": %u, \"ip\": \"%s\" }";
		break;
	}
}

int dp_inspect_init_lb(struct dp_inspect_spec *out_spec, enum dp_inspect_output_format format)
{
	out_spec->table_name = DP_LB_TABLE_NAME;
	out_spec->dump_func = dp_inspect_lb;
	setup_format(out_spec, format);
	return DP_OK;
}

int dp_inspect_init_lb_id(struct dp_inspect_spec *out_spec, enum dp_inspect_output_format format)
{
	out_spec->table_name = DP_LB_ID_TABLE_NAME;
	out_spec->dump_func = dp_inspect_lb_id;
	setup_format(out_spec, format);
	return DP_OK;
}
