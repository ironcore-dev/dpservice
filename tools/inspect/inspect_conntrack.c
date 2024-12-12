// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#include "inspect_conntrack.h"

#include <stdio.h>
#include "dp_error.h"
#include "dp_flow.h"

#include "common_ip.h"
#include "common_vnf.h"

#define CONNTRACK_FORMAT_HUMAN "type: %6s, vni: %3u, proto: %4s, src: %15s:%-5u, dst: %15s:%-5u, port_id: %3u, state: %6s, flags: 0x%02x, aged: %d, age: %02lu:%02lu:%02lu, timeout: %5u, ref_count: %u\n"
#define CONNTRACK_FORMAT_TABLE "%-6s  %3u  %-5s  %15s:%-5u  %15s:%-5u  %7u  %-6s   0x%02x     %d  %02lu:%02lu:%02lu  %7u  %9u\n"
#define CONNTRACK_FORMAT_CSV "%s,%u,%s,%s:%u,%s:%u,%u,%s,0x%02x,%d,%02lu:%02lu:%02lu,%u,%u\n"
#define CONNTRACK_FORMAT_JSON "{ \"type\": \"%s\", \"vni\": %u, \"proto\": \"%s\", \"src\": \"%s:%u\", \"dst\": \"%s:%u\", \"port_id\": %u, \"state\": \"%s\", \"flags\": \"0x%02x\", \"aged\": %d, \"age\": \"%02lu:%02lu:%02lu\", \"timeout\": %u, \"ref_count\": %u }"

#define CONNTRACK_HEADER_HUMAN NULL
#define CONNTRACK_HEADER_TABLE "TYPE    VNI  PROTO            SOURCE            DESTINATION       PORT_ID  STATE   FLAGS  AGED    AGE     TIMEOUT  REF_COUNT\n"
#define CONNTRACK_HEADER_CSV "TYPE,VNI,PROTO,SOURCE,DESTINATION,PORT_ID,STATE,FLAGS,AGED,AGE,TIMEOUT,REF_COUNT\n"
#define CONNTRACK_HEADER_JSON NULL

static const char *conntrack_format_str = CONNTRACK_FORMAT_TABLE;
static const char *conntrack_header_str = CONNTRACK_HEADER_HUMAN;

static void setup_format(enum dp_inspect_output_format format)
{
	switch (format) {
	case DP_INSPECT_OUTPUT_FORMAT_HUMAN:
		conntrack_header_str = CONNTRACK_HEADER_HUMAN;
		conntrack_format_str = CONNTRACK_FORMAT_HUMAN;
		break;
	case DP_INSPECT_OUTPUT_FORMAT_TABLE:
		conntrack_header_str = CONNTRACK_HEADER_TABLE;
		conntrack_format_str = CONNTRACK_FORMAT_TABLE;
		break;
	case DP_INSPECT_OUTPUT_FORMAT_CSV:
		conntrack_header_str = CONNTRACK_HEADER_CSV;
		conntrack_format_str = CONNTRACK_FORMAT_CSV;
		break;
	case DP_INSPECT_OUTPUT_FORMAT_JSON:
		conntrack_header_str = CONNTRACK_HEADER_JSON;
		conntrack_format_str = CONNTRACK_FORMAT_JSON;
		break;
	}
}

static void print_header(void)
{
	if (conntrack_header_str)
		printf(conntrack_header_str);
}


static const char *get_str_state(enum dp_flow_tcp_state state)
{
	switch (state) {
	case DP_FLOW_TCP_STATE_NONE:
		return "none";
	case DP_FLOW_TCP_STATE_NEW_SYN:
		return "syn";
	case DP_FLOW_TCP_STATE_NEW_SYNACK:
		return "synack";
	case DP_FLOW_TCP_STATE_ESTABLISHED:
		return "est";
	case DP_FLOW_TCP_STATE_FINWAIT:
		return "finwai";
	case DP_FLOW_TCP_STATE_RST_FIN:
		return "rstfin";
	}
	return "?";
};

static int dp_inspect_conntrack(const void *key, const void *val)
{
	const struct flow_key *flow_key = key;
	const struct flow_value *flow_val = val;

	char src[INET6_ADDRSTRLEN];
	char dst[INET6_ADDRSTRLEN];

	uint64_t hz = rte_get_tsc_hz();
	uint64_t age = (rte_rdtsc() - flow_val->timestamp) / hz;

	DP_IPADDR_TO_STR(&flow_key->l3_src, src);
	DP_IPADDR_TO_STR(&flow_key->l3_dst, dst);

	printf(conntrack_format_str,
		get_str_vnftype(flow_key->vnf_type),
		flow_key->vni,
		get_str_ipproto(flow_key->proto),
		src, flow_key->src.port_src,
		dst, flow_key->port_dst,
		flow_val->created_port_id,
		get_str_state(flow_val->l4_state.tcp.state),
		flow_val->flow_flags,
		flow_val->aged,
		age / 3600, age / 60 % 60, age % 60,
		flow_val->timeout_value,
		rte_atomic32_read(&flow_val->ref_count.refcount)
	);

	return DP_OK;
}


const struct dp_inspect_spec dp_inspect_conntrack_spec = {
	.table_name = "conntrack_table",
	.dump_func = dp_inspect_conntrack,
	.setup_format_func = setup_format,
	.print_header_func = print_header,
};
