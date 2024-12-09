// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#ifndef __INSPECT_H__
#define __INSPECT_H__

enum dp_inspect_mode {
	DP_INSPECT_COUNT,
	DP_INSPECT_DUMP,
};

enum dp_inspect_output_format {
	DP_INSPECT_OUTPUT_FORMAT_HUMAN,
	DP_INSPECT_OUTPUT_FORMAT_TABLE,
	DP_INSPECT_OUTPUT_FORMAT_CSV,
	DP_INSPECT_OUTPUT_FORMAT_JSON,
};

struct dp_inspect_spec {
	const char *table_name;
	int (*dump_func)(const void *key, const void *val);
	const char *header;
};

int dp_inspect_table(const struct dp_inspect_spec *spec, int numa_socket, enum dp_inspect_mode mode, enum dp_inspect_output_format format);

#endif
