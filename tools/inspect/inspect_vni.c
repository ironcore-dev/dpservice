// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#include "inspect_vni.h"

#include <stdio.h>

#include "dp_error.h"
#include "dp_vni.h"

#define VNI_FORMAT_HUMAN " vni: %3d, data_vni: %3d, socket: %d, rib: %p, rib6: %p, ref_count: %u\n"
#define VNI_FORMAT_TABLE "%3d  %8d  %6d  %18p  %18p  %9u\n"
#define VNI_FORMAT_CSV "%d,%d,%d,%p,%p,%u\n"
#define VNI_FORMAT_JSON "{ \"vni\": %d, \"data_vni\": %d, \"socket\": %d, \"rib\": \"%p\", \"rib6\": \"%p\", \"ref_count\": %u }"

#define VNI_HEADER_HUMAN NULL
#define VNI_HEADER_TABLE "VNI  DATA_VNI  SOCKET                 RIB                RIB6  REF_COUNT\n"
#define VNI_HEADER_CSV "VNI,DATA_VNI,SOCKET,RIB,RIB6,REF_COUNT\n"
#define VNI_HEADER_JSON NULL

static const char *vni_format_str = VNI_FORMAT_TABLE;
static const char *vni_header_str = VNI_HEADER_TABLE;

static void setup_format(enum dp_inspect_output_format format)
{
	switch (format) {
	case DP_INSPECT_OUTPUT_FORMAT_HUMAN:
		vni_header_str = VNI_HEADER_HUMAN;
		vni_format_str = VNI_FORMAT_HUMAN;
		break;
	case DP_INSPECT_OUTPUT_FORMAT_TABLE:
		vni_header_str = VNI_HEADER_TABLE;
		vni_format_str = VNI_FORMAT_TABLE;
		break;
	case DP_INSPECT_OUTPUT_FORMAT_CSV:
		vni_header_str = VNI_HEADER_CSV;
		vni_format_str = VNI_FORMAT_CSV;
		break;
	case DP_INSPECT_OUTPUT_FORMAT_JSON:
		vni_header_str = VNI_HEADER_JSON;
		vni_format_str = VNI_FORMAT_JSON;
		break;
	}
}

static void print_header(void)
{
	if (vni_header_str)
		printf(vni_header_str);
}


static int dp_inspect_vni(const void *key, const void *val)
{
	const struct dp_vni_key *vni_key = key;
	const struct dp_vni_data *vni_data = val;

	printf(vni_format_str,
		vni_key->vni,
		vni_data->vni,
		vni_data->socket_id,
		vni_data->ipv4[DP_SOCKETID(vni_data->socket_id)],
		vni_data->ipv6[DP_SOCKETID(vni_data->socket_id)],
		rte_atomic32_read(&vni_data->ref_count.refcount)
	);
	return DP_OK;
}


const struct dp_inspect_spec dp_inspect_vni_spec = {
	.table_name = "vni_table",
	.dump_func = dp_inspect_vni,
	.setup_format_func = setup_format,
	.print_header_func = print_header,
};
