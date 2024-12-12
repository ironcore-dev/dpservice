// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#include "inspect_vnf.h"

#include <stdio.h>

#include "dp_error.h"
#include "dp_ipaddr.h"

#include "common_vnf.h"

#define VNF_FORMAT_HUMAN " ul: %s, type: %6s, vni: %3u, port_id: %3u, prefix: %15s, length: %u\n"
#define VNF_FORMAT_TABLE "%-39s  %-6s  %3u  %7u  %-15s  %6u\n"
#define VNF_FORMAT_CSV "%s,%s,%u,%u,%s,%u\n"
#define VNF_FORMAT_JSON "{ \"ul\": \"%s\", \"type\": \"%s\", \"vni\": %u, \"port_id\": %u, \"prefix\": \"%s\", \"length\": %u }"

#define VNF_HEADER_HUMAN NULL
#define VNF_HEADER_TABLE "UNDERLAY_IP                              TYPE    VNI  PORT_ID  PREFIX           LENGTH\n"
#define VNF_HEADER_CSV "UNDERLAY_IP,TYPE,VNI,PORT_ID,PREFIX,LENGTH\n"
#define VNF_HEADER_JSON NULL

static const char *vnf_format_str = VNF_FORMAT_TABLE;
static const char *vnf_header_str = VNF_HEADER_TABLE;

static void setup_format(enum dp_inspect_output_format format)
{
	switch (format) {
	case DP_INSPECT_OUTPUT_FORMAT_HUMAN:
		vnf_header_str = VNF_HEADER_HUMAN;
		vnf_format_str = VNF_FORMAT_HUMAN;
		break;
	case DP_INSPECT_OUTPUT_FORMAT_TABLE:
		vnf_header_str = VNF_HEADER_TABLE;
		vnf_format_str = VNF_FORMAT_TABLE;
		break;
	case DP_INSPECT_OUTPUT_FORMAT_CSV:
		vnf_header_str = VNF_HEADER_CSV;
		vnf_format_str = VNF_FORMAT_CSV;
		break;
	case DP_INSPECT_OUTPUT_FORMAT_JSON:
		vnf_header_str = VNF_HEADER_JSON;
		vnf_format_str = VNF_FORMAT_JSON;
		break;
	}
}

static void print_header(void)
{
	if (vnf_header_str)
		printf(vnf_header_str);
}


static void print_vnf(const union dp_ipv6 *ul_addr6, const struct dp_vnf *vnf)
{
	char ul[INET6_ADDRSTRLEN];
	char ol[INET6_ADDRSTRLEN];

	DP_IPV6_TO_STR(ul_addr6, ul);
	DP_IPADDR_TO_STR(&vnf->alias_pfx.ol, ol);

	printf(vnf_format_str,
		ul,
		get_str_vnftype(vnf->type),
		vnf->vni,
		vnf->port_id,
		ol, vnf->alias_pfx.length
	);
}


static int dp_inspect_vnf(const void *key, const void *val)
{
	print_vnf(key, val);
	return DP_OK;
}

static int dp_inspect_vnf_rev(const void *key, const void *val)
{
	print_vnf(val, key);
	return DP_OK;
}


const struct dp_inspect_spec dp_inspect_vnf_spec = {
	.table_name = "vnf_table",
	.dump_func = dp_inspect_vnf,
	.setup_format_func = setup_format,
	.print_header_func = print_header,
};

const struct dp_inspect_spec dp_inspect_vnf_rev_spec = {
	.table_name = "reverse_vnf_table",
	.dump_func = dp_inspect_vnf_rev,
	.setup_format_func = setup_format,
	.print_header_func = print_header,
};
