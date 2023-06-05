#ifndef __INCLUDE_DP_ERROR_H__
#define __INCLUDE_DP_ERROR_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <assert.h>
#include <rte_errno.h>

#define DP_OK 0
#define DP_ERROR (-RTE_MAX_ERRNO)
#define _DP_GRPC_ERRCODES (DP_ERROR-1)

// NOTICE: these can be used directly with a function call, do not use RET multiple times
#define DP_FAILED(RET) \
	((RET) < 0)
#define DP_FAILED_LOG(RET, LOGGER, ...) \
	(DP_FAILED(RET) ? LOGGER(__VA_ARGS__), true : false)

const char *dp_strerror(int error);


/*
 * GRPC error values, do not change them!
 */
// TODO negatives and DP_GRPC_FAILED should all be solved now!
// --> FIRST do proper numbers and pytest, THEN change all if (ret) to DP_FAILED!!!
// this hsould be perfect now!
// TODO merge xNAT_KEY/ALLOC/DATA via a function?
// TODO go through all return GRPC err and look for unnecessary logs (use colored output from pytest too)
#define DP_GRPC_OK							0
#define _DP_GRPC_ERRORS(ERR) \
	/* Returned for unknown request type */ \
	ERR(BAD_REQUEST,						101) \
	/* General-purpose errors */ \
	ERR(NOT_FOUND,							201) \
	ERR(ALREADY_EXISTS,						202) \
	ERR(LIMIT_REACHED,						203) \
	ERR(WRONG_TYPE,							203) \
	ERR(BAD_IPVER,							204) \
	ERR(NO_VM,								205) \
	ERR(NO_VNI,								206) \
	ERR(ITERATOR,							207) \
	ERR(OUT_OF_MEMORY,						208) \
	/* Specific errors */ \
	ERR(ROUTE_EXISTS,						301) \
	ERR(ROUTE_NOT_FOUND,					302) \
	ERR(ROUTE_INSERT,						303) \
	ERR(ROUTE_BAD_PORT,						304) \
	ERR(ROUTE_RESET,						305) \
	ERR(DNAT_KEY,							321) \
	ERR(DNAT_ALLOC,							322) \
	ERR(DNAT_DATA,							323) \
	ERR(DNAT_EXISTS,						324) \
	ERR(SNAT_NO_DATA,						341) \
	ERR(SNAT_NO_KEY,						342) \
	ERR(SNAT_KEY,							343) \
	ERR(SNAT_ALLOC,							344) \
	ERR(SNAT_DATA,							345) \
	ERR(SNAT_EXISTS,						346) \
	ERR(VNI_INIT4,							361) \
	ERR(VNI_INIT6,							362) \
	ERR(VNI_FREE4,							363) \
	ERR(VNI_FREE6,							364) \
	ERR(PORT_START,							381) \
	ERR(PORT_STOP,							382) \
	ERR(VNF_INSERT,							401) \
	ERR(VM_HANDLE,							402) \
	ERR(NO_BACKIP,							421) \
	ERR(NO_DROP_SUPPORT,					441) \

#define _DP_GRPC_ERROR_ENUM(NAME, NUMBER) \
	DP_GRPC_ERR_##NAME = _DP_GRPC_ERRCODES - NUMBER,
enum dp_grpc_error {
	_DP_GRPC_ERRORS(_DP_GRPC_ERROR_ENUM)
};

static inline int dp_errcode_to_grpc_errcode(int dp_errcode)
{
	// should never happen, the programmer must have returned a wrong value
	assert(dp_errcode < _DP_GRPC_ERRCODES);
	return -(dp_errcode - _DP_GRPC_ERRCODES);
}

const char *dp_grpc_strerror(int grpc_errcode);

#ifdef __cplusplus
}
#endif
#endif
