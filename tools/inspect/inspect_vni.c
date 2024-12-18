// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#include "inspect_vni.h"

#include <stdio.h>

#include "dp_error.h"
#include "dp_vni.h"

static const char *g_vni_format;

static int dp_inspect_vni(const void *key, const void *val)
{
	const struct dp_vni_key *vni_key = key;
	const struct dp_vni_data *vni_data = val;

	printf(g_vni_format,
		vni_key->vni,
		vni_data->vni,
		vni_data->socket_id,
		vni_data->ipv4[DP_SOCKETID(vni_data->socket_id)],
		vni_data->ipv6[DP_SOCKETID(vni_data->socket_id)],
		rte_atomic32_read(&vni_data->ref_count.refcount)
	);
	return DP_OK;
}


int dp_inspect_init_vni(struct dp_inspect_spec *out_spec, enum dp_inspect_output_format format)
{
	out_spec->table_name = DP_VNI_TABLE_NAME;
	out_spec->dump_func = dp_inspect_vni;
	switch (format) {
	case DP_INSPECT_OUTPUT_FORMAT_HUMAN:
		out_spec->header = NULL;
		g_vni_format = "vni: %3d, data_vni: %3d, socket: %d, rib: %p, rib6: %p, ref_count: %u\n";
		break;
	case DP_INSPECT_OUTPUT_FORMAT_TABLE:
		out_spec->header = "VNI  DATA_VNI  SOCKET                 RIB                RIB6  REF_COUNT\n";
		g_vni_format = "%3d  %8d  %6d  %18p  %18p  %9u\n";
		break;
	case DP_INSPECT_OUTPUT_FORMAT_CSV:
		out_spec->header = "VNI,DATA_VNI,SOCKET,RIB,RIB6,REF_COUNT\n";
		g_vni_format = "%d,%d,%d,%p,%p,%u\n";
		break;
	case DP_INSPECT_OUTPUT_FORMAT_JSON:
		out_spec->header = NULL;
		g_vni_format = "{ \"vni\": %d, \"data_vni\": %d, \"socket\": %d, \"rib\": \"%p\", \"rib6\": \"%p\", \"ref_count\": %u }";
		break;
	}
	return DP_OK;
}
