#ifndef __INCLUDE_DP_ERROR_H__
#define __INCLUDE_DP_ERROR_H__

#ifdef __cplusplus
extern "C" {
#endif

#define DP_ERROR_VM_ADD					100
#define DP_ERROR_VM_ADD_IPV6_FORMAT		101
#define DP_ERROR_VM_ADD_VM_NAME_ERR		102
#define DP_ERROR_VM_ADD_VM_LPM4			104
#define DP_ERROR_VM_ADD_VM_LPM6			105
#define DP_ERROR_VM_ADD_VM_ADD_ROUT4	106
#define DP_ERROR_VM_ADD_VM_ADD_ROUT6	107
#define DP_ERROR_VM_ADD_VM_NO_VFS		108
#define DP_ERROR_VM_DEL					150
#define DP_ERROR_VM_DEL_VM_NOT_FND		151
#define DP_ERROR_VM_LIST				200
#define DP_ERROR_VM_ADD_RT				250
#define DP_ERROR_VM_ADD_RT_FAIL4		251
#define DP_ERROR_VM_ADD_RT_FAIL6		252

#ifdef __cplusplus
}
#endif
#endif