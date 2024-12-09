// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#include "inspect_vnf.h"

#include <stdio.h>

#include "dp_error.h"
#include "dp_ipaddr.h"

#include "common_vnf.h"

static const char *g_vnf_format;

static void print_vnf(const union dp_ipv6 *ul_addr6, const struct dp_vnf *vnf)
{
	char ul[INET6_ADDRSTRLEN];
	char ol[INET6_ADDRSTRLEN];

	DP_IPV6_TO_STR(ul_addr6, ul);
	DP_IPADDR_TO_STR(&vnf->alias_pfx.ol, ol);

	printf(g_vnf_format,
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


static void setup_format(struct dp_inspect_spec *out_spec, enum dp_inspect_output_format format)
{
	switch (format) {
	case DP_INSPECT_OUTPUT_FORMAT_HUMAN:
		out_spec->header = NULL;
		g_vnf_format = "ul: %39s, type: %6s, vni: %3u, port_id: %3u, prefix: %15s, length: %2u\n";
		break;
	case DP_INSPECT_OUTPUT_FORMAT_TABLE:
		out_spec->header = "UNDERLAY_IP                              TYPE    VNI  PORT_ID  PREFIX           LENGTH\n";
		g_vnf_format = "%-39s  %-6s  %3u  %7u  %-15s  %6u\n";
		break;
	case DP_INSPECT_OUTPUT_FORMAT_CSV:
		out_spec->header = "UNDERLAY_IP,TYPE,VNI,PORT_ID,PREFIX,LENGTH\n";
		g_vnf_format = "%s,%s,%u,%u,%s,%u\n";
		break;
	case DP_INSPECT_OUTPUT_FORMAT_JSON:
		out_spec->header = NULL;
		g_vnf_format = "{ \"ul\": \"%s\", \"type\": \"%s\", \"vni\": %u, \"port_id\": %u, \"prefix\": \"%s\", \"length\": %u }";
		break;
	}
}

int dp_inspect_init_vnf(struct dp_inspect_spec *out_spec, enum dp_inspect_output_format format)
{
	out_spec->table_name = DP_VNF_TABLE_NAME;
	out_spec->dump_func = dp_inspect_vnf;
	setup_format(out_spec, format);
	return DP_OK;
}

int dp_inspect_init_vnf_rev(struct dp_inspect_spec *out_spec, enum dp_inspect_output_format format)
{
	out_spec->table_name = DP_VNF_REVERSE_TABLE_NAME;
	out_spec->dump_func = dp_inspect_vnf_rev;
	setup_format(out_spec, format);
	return DP_OK;
}
