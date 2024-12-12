// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#include "inspect_nat.h"

#include <stdio.h>

#include "dp_error.h"
#include "dp_nat.h"

#include "common_ip.h"

#define DNAT_FORMAT_HUMAN " vip: %15s, vni: %3u, ip: %15s\n"
#define SNAT_FORMAT_HUMAN " vni: %3u, ip: %15s, vip_ip: %15s, nat_ip: %15s, min_port: %5u, max_port: %5u, ul_vip: %s, ul_nat: %s\n"
#define PORTMAP_FORMAT_HUMAN " vni: %3u, src_ip: %15s, src_port: %5u, nat_ip: %15s, nat_port: %5u, flows: %u\n"
#define PORTOVERLOAD_FORMAT_HUMAN " nat_ip: %15s, nat_port: %5u, dst_ip: %15s, dst_port: %5u, proto: %4s\n"

#define DNAT_FORMAT_TABLE "%-15s  %3u  %-15s\n"
#define SNAT_FORMAT_TABLE "%3u  %-15s  %-15s  %-15s  %8u  %8u  %-39s  %-39s\n"
#define PORTMAP_FORMAT_TABLE "%3u  %-15s  %8u  %-15s  %8u  %5u\n"
#define PORTOVERLOAD_FORMAT_TABLE "%-15s  %8u  %-15s  %8u  %-5s\n"

#define DNAT_FORMAT_CSV "%s,%u,%s\n"
#define SNAT_FORMAT_CSV "%u,%s,%s,%s,%u,%u,%s,%s\n"
#define PORTMAP_FORMAT_CSV "%u,%s,%u,%s,%u,%u\n"
#define PORTOVERLOAD_FORMAT_CSV "%s,%u,%s,%u,%s\n"

#define DNAT_FORMAT_JSON "{ \"vip\": \"%s\", \"vni\": %u, \"ip\": \"%s\" }"
#define SNAT_FORMAT_JSON "{ \"vni\": %u, \"ip\": \"%s\", \"vip_ip\": \"%s\", \"nat_ip\": \"%s\", \"min_port\": %u, \"max_port\": %u, \"ul_vip\": \"%s\", \"ul_nat\": \"%s\" }"
#define PORTMAP_FORMAT_JSON "{ \"vni\": %u, \"src_ip\": \"%s\", \"src_port\": %u, \"nat_ip\": \"%s\", \"nat_port\": %u, \"flows\": %u }"
#define PORTOVERLOAD_FORMAT_JSON "{ \"nat_ip\": \"%s\", \"nat_port\": %u, \"dst_ip\": \"%s\", \"dst_port\": %u, \"proto\": \"%s\" }"

#define DNAT_HEADER_HUMAN NULL
#define DNAT_HEADER_TABLE "VIP              VNI  IP\n"
#define DNAT_HEADER_CSV "VIP,VNI,IP\n"
#define DNAT_HEADER_JSON NULL

#define SNAT_HEADER_HUMAN NULL
#define SNAT_HEADER_TABLE "VNI  IP               VIP_IP           NAT_IP           MIN_PORT  MAX_PORT  UL_VIP                                   UL_NAT\n"
#define SNAT_HEADER_CSV "VNI,IP,VIP_IP,NAT_IP,MIN_PORT,MAX_PORT,UL_VIP,UL_NAT\n"
#define SNAT_HEADER_JSON NULL

#define PORTMAP_HEADER_HUMAN NULL
#define PORTMAP_HEADER_TABLE "VNI  SRC_IP           SRC_PORT  NAT_IP           NAT_PORT  FLOWS\n"
#define PORTMAP_HEADER_CSV "VNI,SRC_IP,SRC_PORT,NAT_IP,NAT_PORT,FLOWS\n"
#define PORTMAP_HEADER_JSON NULL

#define PORTOVERLOAD_HEADER_HUMAN NULL
#define PORTOVERLOAD_HEADER_TABLE "NAT_IP           NAT_PORT  DST_IP           DST_PORT  PROTO\n"
#define PORTOVERLOAD_HEADER_CSV "NAT_IP,NAT_PORT,DST_IP,DST_PORT,PROTO\n"
#define PORTOVERLOAD_HEADER_JSON NULL

static const char *dnat_format_str = DNAT_FORMAT_HUMAN;
static const char *snat_format_str = SNAT_FORMAT_HUMAN;
static const char *portmap_format_str = PORTMAP_FORMAT_HUMAN;
static const char *portoverload_format_str = PORTOVERLOAD_FORMAT_HUMAN;

static const char *dnat_header_str = DNAT_HEADER_HUMAN;
static const char *snat_header_str = SNAT_HEADER_HUMAN;
static const char *portmap_header_str = PORTMAP_HEADER_HUMAN;
static const char *portoverload_header_str = PORTOVERLOAD_HEADER_HUMAN;

static void setup_format(enum dp_inspect_output_format format)
{
	switch (format) {
	case DP_INSPECT_OUTPUT_FORMAT_HUMAN:
		dnat_header_str = DNAT_HEADER_HUMAN;
		snat_header_str = SNAT_HEADER_HUMAN;
		portmap_header_str = PORTMAP_HEADER_HUMAN;
		portoverload_header_str = PORTOVERLOAD_HEADER_HUMAN;
		dnat_format_str = DNAT_FORMAT_HUMAN;
		snat_format_str = SNAT_FORMAT_HUMAN;
		portmap_format_str = PORTMAP_FORMAT_HUMAN;
		portoverload_format_str = PORTOVERLOAD_FORMAT_HUMAN;
		break;
	case DP_INSPECT_OUTPUT_FORMAT_TABLE:
		dnat_header_str = DNAT_HEADER_TABLE;
		snat_header_str = SNAT_HEADER_TABLE;
		portmap_header_str = PORTMAP_HEADER_TABLE;
		portoverload_header_str = PORTOVERLOAD_HEADER_TABLE;
		dnat_format_str = DNAT_FORMAT_TABLE;
		snat_format_str = SNAT_FORMAT_TABLE;
		portmap_format_str = PORTMAP_FORMAT_TABLE;
		portoverload_format_str = PORTOVERLOAD_FORMAT_TABLE;
		break;
	case DP_INSPECT_OUTPUT_FORMAT_CSV:
		dnat_header_str = DNAT_HEADER_CSV;
		snat_header_str = SNAT_HEADER_CSV;
		portmap_header_str = PORTMAP_HEADER_CSV;
		portoverload_header_str = PORTOVERLOAD_HEADER_CSV;
		dnat_format_str = DNAT_FORMAT_CSV;
		snat_format_str = SNAT_FORMAT_CSV;
		portmap_format_str = PORTMAP_FORMAT_CSV;
		portoverload_format_str = PORTOVERLOAD_FORMAT_CSV;
		break;
	case DP_INSPECT_OUTPUT_FORMAT_JSON:
		dnat_header_str = DNAT_HEADER_JSON;
		snat_header_str = SNAT_HEADER_JSON;
		portmap_header_str = PORTMAP_HEADER_JSON;
		portoverload_header_str = PORTOVERLOAD_HEADER_JSON;
		dnat_format_str = DNAT_FORMAT_JSON;
		snat_format_str = SNAT_FORMAT_JSON;
		portmap_format_str = PORTMAP_FORMAT_JSON;
		portoverload_format_str = PORTOVERLOAD_FORMAT_JSON;
		break;
	}
}

static void print_header_dnat(void)
{
	if (dnat_header_str)
		printf(dnat_header_str);
}

static void print_header_snat(void)
{
	if (snat_header_str)
		printf(snat_header_str);
}

static void print_header_portmap(void)
{
	if (portmap_header_str)
		printf(portmap_header_str);
}

static void print_header_portoverload(void)
{
	if (portoverload_header_str)
		printf(portoverload_header_str);
}


static int dp_inspect_dnat(const void *key, const void *val)
{
	const struct nat_key *nat_key = key;
	const struct dnat_data *dnat_data = val;

	char ip[INET_ADDRSTRLEN];
	char vip[INET_ADDRSTRLEN];

	DP_IPV4_TO_STR(nat_key->ip, vip);
	DP_IPV4_TO_STR(dnat_data->dnat_ip, ip);
	printf(dnat_format_str,
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
	printf(snat_format_str,
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
	printf(portmap_format_str,
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
	printf(portoverload_format_str,
		nat_ip, pkey->nat_port,
		dst_ip, pkey->dst_port,
		get_str_ipproto(pkey->l4_type)
	);
	return DP_OK;
}


// TODO global problem: define names in dpservice
const struct dp_inspect_spec dp_inspect_dnat_spec = {
	.table_name = "dnat_table",
	.dump_func = dp_inspect_dnat,
	.setup_format_func = setup_format,
	.print_header_func = print_header_dnat,
};

const struct dp_inspect_spec dp_inspect_snat_spec = {
	.table_name = "snat_table",
	.dump_func = dp_inspect_snat,
	.setup_format_func = setup_format,
	.print_header_func = print_header_snat,
};

const struct dp_inspect_spec dp_inspect_portmap_spec = {
	.table_name = "nat_portmap_table",
	.dump_func = dp_inspect_portmap,
	.setup_format_func = setup_format,
	.print_header_func = print_header_portmap,
};

const struct dp_inspect_spec dp_inspect_portoverload_spec = {
	.table_name = "nat_portoverload_table",
	.dump_func = dp_inspect_portoverload,
	.setup_format_func = setup_format,
	.print_header_func = print_header_portoverload,
};
