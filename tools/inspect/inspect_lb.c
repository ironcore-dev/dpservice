// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#include "inspect_lb.h"

#include <stdio.h>

#include "dp_error.h"
#include "dp_ipaddr.h"
#include "dp_lb.h"

#define LB_FORMAT_HUMAN " lb_id: %.*s, vni: %3u, ip: %15s\n"
#define LB_FORMAT_TABLE "%-36.*s  %3u  %s\n"
#define LB_FORMAT_CSV "%.*s,%u,%s\n"
#define LB_FORMAT_JSON "{ \"lb_id\": \"%.*s\", \"vni\": %u, \"ip\": \"%s\" }"

#define LB_HEADER_HUMAN NULL
#define LB_HEADER_TABLE "LB_ID                                 VNI  IP\n"
#define LB_HEADER_CSV "LB_ID,VNI,IP\n"
#define LB_HEADER_JSON NULL

static const char *lb_format_str = LB_FORMAT_TABLE;
static const char *lb_header_str = LB_HEADER_TABLE;

static void setup_format(enum dp_inspect_output_format format)
{
	switch (format) {
	case DP_INSPECT_OUTPUT_FORMAT_HUMAN:
		lb_header_str = LB_HEADER_HUMAN;
		lb_format_str = LB_FORMAT_HUMAN;
		break;
	case DP_INSPECT_OUTPUT_FORMAT_TABLE:
		lb_header_str = LB_HEADER_TABLE;
		lb_format_str = LB_FORMAT_TABLE;
		break;
	case DP_INSPECT_OUTPUT_FORMAT_CSV:
		lb_header_str = LB_HEADER_CSV;
		lb_format_str = LB_FORMAT_CSV;
		break;
	case DP_INSPECT_OUTPUT_FORMAT_JSON:
		lb_header_str = LB_HEADER_JSON;
		lb_format_str = LB_FORMAT_JSON;
		break;
	}
}

static void print_header(void)
{
	if (lb_header_str)
		printf(lb_header_str);
}


static int dp_inspect_lb(const void *key, const void *val)
{
	const struct lb_key *lb_key = key;
	const struct lb_value *lb_val = val;

	char ip[INET6_ADDRSTRLEN];

	DP_IPADDR_TO_STR(&lb_key->ip, ip);
	printf(lb_format_str,
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
	printf(lb_format_str,
		DP_LB_ID_MAX_LEN, lb_id,
		lb_key->vni,
		ip
	);
	return DP_OK;
}


const struct dp_inspect_spec dp_inspect_lb_spec = {
	.table_name = "loadbalancer_table",
	.dump_func = dp_inspect_lb,
	.setup_format_func = setup_format,
	.print_header_func = print_header,
};

const struct dp_inspect_spec dp_inspect_lb_id_spec = {
	.table_name = "loadbalancer_id_table",
	.dump_func = dp_inspect_lb_id,
	.setup_format_func = setup_format,
	.print_header_func = print_header,
};
