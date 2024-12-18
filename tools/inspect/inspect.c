// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#include "inspect.h"

#include <rte_hash.h>

#include "dp_error.h"
#include "dp_ipaddr.h"
#include "dp_util.h"

// HACK HACK HACK to make including dp_ipaddr.h work
const union dp_ipv6 *dp_conf_get_underlay_ip(void);
const union dp_ipv6 *dp_conf_get_underlay_ip(void)
{
	return &dp_empty_ipv6;
}


static int dp_dump_table(const struct rte_hash *htable, int (*dumpfunc)(const void *key, const void *val), enum dp_inspect_output_format format)
{
	uint32_t iter = 0;
	void *val = NULL;
	const void *key;
	bool first = true;
	int ret;

	if (format == DP_INSPECT_OUTPUT_FORMAT_JSON)
		printf("[\n");

	while ((ret = rte_hash_iterate(htable, (const void **)&key, (void **)&val, &iter)) != -ENOENT) {
		if (DP_FAILED(ret)) {
			fprintf(stderr, "Iterating table failed with %d\n", ret);
			return ret;
		}
		if (format == DP_INSPECT_OUTPUT_FORMAT_JSON) {
			if (unlikely(first)) {
				first = false;
				printf("\t");
			} else {
				printf(",\n\t");
			}
		}
		if (DP_FAILED(dumpfunc(key, val))) {
			fprintf(stderr, "Dumping table failed with %d\n", ret);
			return ret;
		}
	}

	if (format == DP_INSPECT_OUTPUT_FORMAT_JSON)
		printf("\n]\n");

	return DP_OK;
}

static int dp_count_table(const char *full_name, const struct rte_hash *htable, enum dp_inspect_output_format format)
{
	int32_t count = rte_hash_count(htable);

	switch (format) {
	case DP_INSPECT_OUTPUT_FORMAT_HUMAN:
		printf("Table '%s' has %u entries\n", full_name, count);
		break;
	case DP_INSPECT_OUTPUT_FORMAT_TABLE:
		printf("%*s  ENTRIES\n%s  %u\n", -(int)strlen(full_name), "TABLE", full_name, count);
		break;
	case DP_INSPECT_OUTPUT_FORMAT_CSV:
		printf("TABLE,ENTRIES\n%s,%u\n", full_name, count);
		break;
	case DP_INSPECT_OUTPUT_FORMAT_JSON:
		printf("{ \"table\": \"%s\", \"entries\": %u }\n", full_name, count);
		break;
	}
	return DP_OK;
}

int dp_inspect_table(const struct dp_inspect_spec *spec, int numa_socket, enum dp_inspect_mode mode, enum dp_inspect_output_format format)
{
	struct rte_hash *htable;
	char full_name[RTE_HASH_NAMESIZE];
	int ret = DP_OK;

	if (DP_FAILED(dp_get_jhash_table_full_name(spec->table_name, numa_socket, full_name, sizeof(full_name)))) {
		fprintf(stderr, "jhash table name '%s' is too long\n", spec->table_name);
		return DP_ERROR;
	}

	htable = rte_hash_find_existing(full_name);
	if (!htable) {
		fprintf(stderr, "Table '%s' not found, maybe the NUMA socket is wrong?\n", full_name);
		return DP_ERROR;
	}

	switch (mode) {
	case DP_INSPECT_COUNT:
		ret = dp_count_table(full_name, htable, format);
		break;
	case DP_INSPECT_DUMP:
		if (spec->header)
			printf("%s", spec->header);
		ret = dp_dump_table(htable, spec->dump_func, format);
		if (format == DP_INSPECT_OUTPUT_FORMAT_TABLE && spec->header)
			printf("%s", spec->header);
		break;
	}

	return ret;
}
