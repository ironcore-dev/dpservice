// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#include "dp_argparse.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dp_error.h"

/* NOTE: This module uses plain printf() because it is being used by other tools, not just dp-service */

int dp_argparse_string(const char *arg, char *dst, size_t dst_size)
{
	size_t len = strlen(arg);

	if (len >= dst_size) {
		fprintf(stderr, "Value '%s' is too long (max %lu characters)\n", arg, dst_size-1);
		return DP_ERROR;
	}

	memcpy(dst, arg, len+1);  // including \0
	return DP_OK;
}

int dp_argparse_int(const char *arg, int *dst, int min, int max)
{
	long result;
	char *endptr;

	result = strtol(arg, &endptr, 10);
	if (*endptr) {
		fprintf(stderr, "Value '%s' is not an integer\n", arg);
		return DP_ERROR;
	}
	if (result < min || result > max) {
		fprintf(stderr, "Value '%s' is out of range (%d-%d)\n", arg, min, max);
		return DP_ERROR;
	}

	*dst = (int)result;  // this is fine, limited by min/max
	return DP_OK;
}

int dp_argparse_enum(const char *arg, int *dst, const char *choices[], size_t choice_count)
{
	for (size_t i = 0; i < choice_count; ++i) {
		if (!strcmp(choices[i], arg)) {
			*dst = (int)i;
			return DP_OK;
		}
	}
	fprintf(stderr, "Invalid choice '%s' (choose from:", arg);
	for (size_t i = 0; i < choice_count; ++i)
		fprintf(stderr, "%s '%s'", i > 0 ? "," : "", choices[i]);
	fprintf(stderr, ")\n");
	return DP_ERROR;
}
