#ifdef DEBUG
	// enable GNU extension strerrorname_np()
#	ifndef _GNU_SOURCE
#		define _GNU_SOURCE
#		include <string.h>
#		undef _GNU_SOURCE
#	else
#		include <string.h>
#	endif
#endif

#include "dp_error.h"
#include <stdio.h>
#include <rte_common.h>

// rte_strerror() uses 256, we add a number and (optionally) a short name
#define STRERROR_BUFSIZE 320

#define _DP_GRPC_ERROR_STRING(NAME, NUMBER) \
	[NUMBER] = #NAME,
static const char *dp_grpc_error_strings[] = {
	_DP_GRPC_ERRORS(_DP_GRPC_ERROR_STRING)
};

const char *dp_grpc_strerror(int grpc_errcode)
{
	if (grpc_errcode == DP_GRPC_OK)
		return "Success";
	if (grpc_errcode < 0 || grpc_errcode >= (int)RTE_DIM(dp_grpc_error_strings) || !dp_grpc_error_strings[grpc_errcode]) {
		// this should never happen, the programmer must have returned a wrong value
		assert("Invalid gRPC error code provided" == NULL);
		return "Invalid gRPC error code";
	}
	return dp_grpc_error_strings[grpc_errcode];
}

const char *dp_strerror(int error)
{
	if (error < 0)
		error = -error;

	if (error < RTE_MAX_ERRNO)
		return rte_strerror(error);
	else if (error >= -_DP_GRPC_ERRCODES)
		return dp_grpc_strerror(error+_DP_GRPC_ERRCODES);
	else
		return "General dpservice error";
}

const char *dp_strerror_verbose(int error)
{
	static __thread char buf[STRERROR_BUFSIZE];
	const char *errdesc;

	if (error < 0)
		error = -error;

	errdesc = dp_strerror(error);

	// print the textual errno for easier debugging
#if defined(DEBUG) && __GLIBC_PREREQ(2, 32)
	const char *errname = strerrorname_np(error);

	if (errname)
		snprintf(buf, sizeof(buf), "(Error %d/%s: %s)", error, errname, errdesc);
	else
#endif
	snprintf(buf, sizeof(buf), "(Error %d: %s)", error, errdesc);

	return buf;
}
