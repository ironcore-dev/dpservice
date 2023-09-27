#ifndef __DP_ARGPARSE_H__
#define __DP_ARGPARSE_H__

#include <stddef.h>
#include <stdbool.h>

#include "dp_error.h"

#ifdef __cplusplus
extern "C" {
#endif

static inline int dp_argparse_store_true(bool *dst)
{
	*dst = true;
	return DP_OK;
}

static inline int dp_argparse_store_false(bool *dst)
{
	*dst = false;
	return DP_OK;
}

int dp_argparse_string(const char *arg, char *dst, size_t dst_size);

int dp_argparse_int(const char *arg, int *dst, int min, int max);

int dp_argparse_enum(const char *arg, int *dst, const char *choices[], size_t choice_count);

#ifdef __cplusplus
}
#endif

#endif
