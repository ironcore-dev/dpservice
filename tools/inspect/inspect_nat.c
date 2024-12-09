// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#include "inspect_nat.h"

#include <stdio.h>

#include "dp_error.h"
#include "dp_nat.h"

#include "common_ip.h"

static const char *g_dnat_format;
static const char *g_snat_format;
static const char *g_portmap_format;
static const char *g_portoverload_format;

static int dp_inspect_dnat(const void *key, const void *val)
{
	const struct nat_key *nat_key = key;
	const struct dnat_data *dnat_data = val;

	char ip[INET_ADDRSTRLEN];
	char vip[INET_ADDRSTRLEN];

	DP_IPV4_TO_STR(nat_key->ip, vip);
	DP_IPV4_TO_STR(dnat_data->dnat_ip, ip);
	printf(g_dnat_format,
		vip,
		nat_key->vni,
		ip
	);
	return DP_OK;
}

static int dp_inspect_snat(const void *key, const void *val)
{
	const struct nat_key *nat_key = key;
	const struct snat_data *snat_data = val;

	char ip[INET_ADDRSTRLEN];
	char vip_ip[INET_ADDRSTRLEN];
	char nat_ip[INET_ADDRSTRLEN];
	char ul_vip[INET6_ADDRSTRLEN];
	char ul_nat[INET6_ADDRSTRLEN];

	DP_IPV4_TO_STR(nat_key->ip, ip);
	DP_IPV4_TO_STR(snat_data->vip_ip, vip_ip);
	DP_IPV4_TO_STR(snat_data->nat_ip, nat_ip);
	DP_IPV6_TO_STR(&snat_data->ul_vip_ip6, ul_vip);
	DP_IPV6_TO_STR(&snat_data->ul_nat_ip6, ul_nat);
	printf(g_snat_format,
		nat_key->vni,
		ip,
		vip_ip,
		nat_ip,
		snat_data->nat_port_range[0],
		snat_data->nat_port_range[1],
		ul_vip,
		ul_nat
	);
	return DP_OK;
}

static int dp_inspect_portmap(const void *key, const void *val)
{
	const struct netnat_portmap_key *portmap_key = key;
	const struct netnat_portmap_data *portmap_data = val;

	char src_ip[INET6_ADDRSTRLEN];
	char nat_ip[INET_ADDRSTRLEN];

	DP_IPADDR_TO_STR(&portmap_key->src_ip, src_ip);
	DP_IPV4_TO_STR(portmap_data->nat_ip, nat_ip);
	printf(g_portmap_format,
		portmap_key->vni,
		src_ip,
		portmap_key->iface_src_port,
		nat_ip,
		portmap_data->nat_port,
		portmap_data->flow_cnt
	);
	return DP_OK;
}

static int dp_inspect_portoverload(const void *key, const void *val)
{
	const struct netnat_portoverload_tbl_key *pkey = key;

	char nat_ip[INET6_ADDRSTRLEN];
	char dst_ip[INET6_ADDRSTRLEN];

	(void)val;  // apparently no data here

	DP_IPV4_TO_STR(pkey->nat_ip, nat_ip);
	DP_IPV4_TO_STR(pkey->dst_ip, dst_ip);
	printf(g_portoverload_format,
		nat_ip, pkey->nat_port,
		dst_ip, pkey->dst_port,
		get_str_ipproto(pkey->l4_type)
	);
	return DP_OK;
}


int dp_inspect_init_dnat(struct dp_inspect_spec *out_spec, enum dp_inspect_output_format format)
{
	out_spec->table_name = DP_NAT_DNAT_TABLE_NAME;
	out_spec->dump_func = dp_inspect_dnat;
	switch (format) {
	case DP_INSPECT_OUTPUT_FORMAT_HUMAN:
		out_spec->header = NULL;
		g_dnat_format = "vip: %15s, vni: %3u, ip: %15s\n";
		break;
	case DP_INSPECT_OUTPUT_FORMAT_TABLE:
		out_spec->header = "VIP              VNI  IP\n";
		g_dnat_format = "%-15s  %3u  %-15s\n";
		break;
	case DP_INSPECT_OUTPUT_FORMAT_CSV:
		out_spec->header = "VIP,VNI,IP\n";
		g_dnat_format = "%s,%u,%s\n";
		break;
	case DP_INSPECT_OUTPUT_FORMAT_JSON:
		out_spec->header = NULL;
		g_dnat_format = "{ \"vip\": \"%s\", \"vni\": %u, \"ip\": \"%s\" }";
		break;
	}
	return DP_OK;
}

int dp_inspect_init_snat(struct dp_inspect_spec *out_spec, enum dp_inspect_output_format format)
{
	out_spec->table_name = DP_NAT_SNAT_TABLE_NAME;
	out_spec->dump_func = dp_inspect_snat;
	switch (format) {
	case DP_INSPECT_OUTPUT_FORMAT_HUMAN:
		out_spec->header = NULL;
		g_snat_format = "vni: %3u, ip: %15s, vip_ip: %15s, nat_ip: %15s, min_port: %5u, max_port: %5u, ul_vip: %s, ul_nat: %s\n";
		break;
	case DP_INSPECT_OUTPUT_FORMAT_TABLE:
		out_spec->header = "VNI  IP               VIP_IP           NAT_IP           MIN_PORT  MAX_PORT  UL_VIP                                   UL_NAT\n";
		g_snat_format = "%3u  %-15s  %-15s  %-15s  %8u  %8u  %-39s  %-39s\n";
		break;
	case DP_INSPECT_OUTPUT_FORMAT_CSV:
		out_spec->header = "VNI,IP,VIP_IP,NAT_IP,MIN_PORT,MAX_PORT,UL_VIP,UL_NAT\n";
		g_snat_format = "%u,%s,%s,%s,%u,%u,%s,%s\n";
		break;
	case DP_INSPECT_OUTPUT_FORMAT_JSON:
		out_spec->header = NULL;
		g_snat_format = "{ \"vni\": %u, \"ip\": \"%s\", \"vip_ip\": \"%s\", \"nat_ip\": \"%s\", \"min_port\": %u, \"max_port\": %u, "
						"\"ul_vip\": \"%s\", \"ul_nat\": \"%s\" }";
		break;
	}
	return DP_OK;
}

int dp_inspect_init_portmap(struct dp_inspect_spec *out_spec, enum dp_inspect_output_format format)
{
	out_spec->table_name = DP_NAT_PORTMAP_TABLE_NAME;
	out_spec->dump_func = dp_inspect_portmap;
	switch (format) {
	case DP_INSPECT_OUTPUT_FORMAT_HUMAN:
		out_spec->header = NULL;
		g_portmap_format = "vni: %3u, src_ip: %15s, src_port: %5u, nat_ip: %15s, nat_port: %5u, flows: %u\n";
		break;
	case DP_INSPECT_OUTPUT_FORMAT_TABLE:
		out_spec->header = "VNI  SRC_IP           SRC_PORT  NAT_IP           NAT_PORT  FLOWS\n";
		g_portmap_format = "%3u  %-15s  %8u  %-15s  %8u  %5u\n";
		break;
	case DP_INSPECT_OUTPUT_FORMAT_CSV:
		out_spec->header = "VNI,SRC_IP,SRC_PORT,NAT_IP,NAT_PORT,FLOWS\n";
		g_portmap_format = "%u,%s,%u,%s,%u,%u\n";
		break;
	case DP_INSPECT_OUTPUT_FORMAT_JSON:
		out_spec->header = NULL;
		g_portmap_format = "{ \"vni\": %u, \"src_ip\": \"%s\", \"src_port\": %u, \"nat_ip\": \"%s\", \"nat_port\": %u, \"flows\": %u }";
		break;
	}
	return DP_OK;
}

int dp_inspect_init_portoverload(struct dp_inspect_spec *out_spec, enum dp_inspect_output_format format)
{
	out_spec->table_name = DP_NAT_PORTOVERLOAD_TABLE_NAME;
	out_spec->dump_func = dp_inspect_portoverload;
	switch (format) {
	case DP_INSPECT_OUTPUT_FORMAT_HUMAN:
		out_spec->header = NULL;
		g_portoverload_format = "nat_ip: %15s, nat_port: %5u, dst_ip: %15s, dst_port: %5u, proto: %4s\n";
		break;
	case DP_INSPECT_OUTPUT_FORMAT_TABLE:
		out_spec->header = "NAT_IP           NAT_PORT  DST_IP           DST_PORT  PROTO\n";
		g_portoverload_format = "%-15s  %8u  %-15s  %8u  %-5s\n";
		break;
	case DP_INSPECT_OUTPUT_FORMAT_CSV:
		out_spec->header = "NAT_IP,NAT_PORT,DST_IP,DST_PORT,PROTO\n";
		g_portoverload_format = "%s,%u,%s,%u,%s\n";
		break;
	case DP_INSPECT_OUTPUT_FORMAT_JSON:
		out_spec->header = NULL;
		g_portoverload_format = "{ \"nat_ip\": \"%s\", \"nat_port\": %u, \"dst_ip\": \"%s\", \"dst_port\": %u, \"proto\": \"%s\" }";
		break;
	}
	return DP_OK;
}
