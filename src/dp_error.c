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

// rte_strerror() uses 256, we add a number and (optionally) a short name
#define STRERROR_BUFSIZE 320

const char *dp_strerror(int error)
{
	static __thread char buf[STRERROR_BUFSIZE];
	const char *errdesc;

	if (error < 0)
		error = -error;

	// dp_service specific errors are after rte_ errors (which are after __ELASTERROR)
	errdesc = error == RTE_MAX_ERRNO
		? "General dp_service error"
		: rte_strerror(error);

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
