// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#include "dp_secondary_eal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <rte_common.h>
#include <rte_eal.h>
#include "dp_error.h"

// EAL needs writable arguments (both the string and the array!)
// therefore convert them from literals and remember them for freeing later
static const char *eal_arg_strings[] = {
	"dpservice-dump",				// this binary (not used, can actually be any string)
	"--proc-type=secondary",		// connect to the primary process (dpservice-bin) instead
	"--no-pci",						// do not try to use any hardware
	"--log-level=6",				// hide DPDK's informational messages (level 7)
};

static char *eal_args_mem[RTE_DIM(eal_arg_strings) + 1];  // +1 for optional --file-prefix
static char *eal_args[RTE_DIM(eal_args_mem)];


int dp_secondary_eal_init(const char *file_prefix)
{
	char eal_file_prefix[64] = {};

	// Required arguments
	for (size_t i = 0; i < RTE_DIM(eal_arg_strings); ++i) {
		eal_args[i] = eal_args_mem[i] = strdup(eal_arg_strings[i]);
		if (!eal_args[i]) {
			fprintf(stderr, "Cannot allocate EAL arguments\n");
			for (size_t j = 0; j < RTE_DIM(eal_args_mem); ++j)
				free(eal_args_mem[j]);
			return DP_ERROR;
		}
	}

	// Optional arguments
	if (file_prefix && *file_prefix)
		snprintf(eal_file_prefix, sizeof(eal_file_prefix), "--file-prefix=%s", file_prefix);  // can get cut off, but file_prefix length is limited by argparse
	eal_args[RTE_DIM(eal_arg_strings)] = eal_args_mem[RTE_DIM(eal_arg_strings)] = strdup(eal_file_prefix);

	return rte_eal_init(RTE_DIM(eal_args), eal_args);
}


void dp_secondary_eal_cleanup(void)
{
	rte_eal_cleanup();
	for (size_t i = 0; i < RTE_DIM(eal_args_mem); ++i)
		free(eal_args_mem[i]);
}
