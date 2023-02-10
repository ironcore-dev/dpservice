#ifndef __INCLUDE_DP_ERROR_H__
#define __INCLUDE_DP_ERROR_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <rte_errno.h>

#define DP_OK 0
#define DP_ERROR (-RTE_MAX_ERRNO)

// NOTICE: these can be used directly with a function call, do not use RET multiple times
#define DP_FAILED(RET) \
	((RET) < 0)
#define DP_FAILED_LOG(RET, LOGGER, ...) \
	(DP_FAILED(RET) ? LOGGER(__VA_ARGS__), true : false)

const char *dp_strerror(int error);


// TODO(plague): separate PR - add strerror for these
/*
 * GRPC error values, do not change them!
 */
#define DP_ERROR_VM_ADD								100
#define DP_ERROR_VM_ADD_IPV6_FORMAT					101
#define DP_ERROR_VM_ADD_VM_NAME_ERR					102
#define DP_ERROR_VM_ADD_VM_LPM4						104
#define DP_ERROR_VM_ADD_VM_LPM6						105
#define DP_ERROR_VM_ADD_VM_ADD_ROUT4				106
#define DP_ERROR_VM_ADD_VM_ADD_ROUT6				107
#define DP_ERROR_VM_ADD_VM_NO_VFS					108
#define DP_ERROR_VM_ALREADY_ALLOCATED				109
#define DP_ERROR_VM_CANT_GET_NAME					110
#define DP_ERROR_VM_DEL								150
#define DP_ERROR_VM_DEL_VM_NOT_FND					151
#define DP_ERROR_VM_GET_VM_NOT_FND					171
#define DP_ERROR_VM_LIST							200
#define DP_ERROR_VM_ADD_RT							250
#define DP_ERROR_VM_ADD_RT_FAIL4					251
#define DP_ERROR_VM_ADD_RT_FAIL6					252
#define DP_ERROR_VM_ADD_RT_NO_VM					253
#define DP_ERROR_VM_DEL_RT							300
#define DP_ERROR_VM_GET_NETNAT_ITER_ERROR			349
#define DP_ERROR_VM_ADD_NAT							350
#define DP_ERROR_VM_ADD_NAT_IP_EXISTS				351
#define DP_ERROR_VM_ADD_NAT_ALLOC					352
#define DP_ERROR_VM_ADD_NAT_ADD_KEY					353
#define DP_ERROR_VM_ADD_NET_NAT_DATA				354
#define DP_ERROR_VM_ADD_NETWORK_NAT					355
#define DP_ERROR_VM_DEL_NETWORK_NAT					356
#define DP_ERROR_VM_ADD_NETNAT_NONLOCAL 			357
#define DP_ERROR_VM_ADD_NETNAT_INVALID_PORT			358
#define DP_ERROR_VM_ADD_NETNAT_DATA_NOT_FOUND		359
#define DP_ERROR_VM_DEL_NETNAT_NONLOCAL				360
#define DP_ERROR_VM_DEL_NETNAT_INVALID_PORT			361
#define DP_ERROR_VM_DEL_NETNAT_ENTRY_NOT_FOUND		362
#define DP_ERROR_VM_ADD_NETNAT_IP_EXISTS			363
#define DP_ERROR_VM_ADD_NETNAT_KEY					364
#define DP_ERROR_VM_ADD_NETNAT_ALLO_DATA			365
#define DP_ERROR_VM_ADD_NETNAT_ADD_DATA				366
#define DP_ERROR_VM_DEL_NETNAT_KEY_DELETED			367
#define DP_ERROR_VM_GET_NETNAT_IPV6_UNSUPPORTED		369
#define DP_ERROR_VM_ADD_NEIGHNAT_WRONGTYPE			370
#define DP_ERROR_VM_DEL_NEIGHNAT_WRONGTYPE			371
#define DP_ERROR_VM_ADD_NEIGHNAT_ENTRY_EXIST 		372
#define DP_ERROR_VM_ADD_NEIGHNAT_ALLOC		 		373
#define DP_ERROR_VM_DEL_NEIGHNAT_ENTRY_NOFOUND		374
#define DP_ERROR_VM_GET_NEIGHNAT_UNDER_IPV6			375
#define DP_ERROR_VM_GET_NETNAT_INFO_TYPE_UNKNOWN	369
#define DP_ERROR_VM_ADD_DNAT						400
#define DP_ERROR_VM_ADD_DNAT_IP_EXISTS				401
#define DP_ERROR_VM_ADD_DNAT_ALLOC					402
#define DP_ERROR_VM_ADD_DNAT_ADD_KEY				403
#define DP_ERROR_VM_ADD_DNAT_ADD_DATA				404
#define DP_ERROR_VM_DEL_NAT							450
#define DP_ERROR_VM_GET_NAT							500
#define DP_ERROR_VM_GET_NAT_NO_IP_SET				501
#define DP_ERROR_VM_ADD_LB_VIP						550
#define DP_ERROR_VM_ADD_LB_NO_VNI_EXIST				551
#define DP_ERROR_VM_ADD_LB_UNSUPP_IP				552
#define DP_ERROR_VM_DEL_LB_VIP						600
#define DP_ERROR_VM_DEL_LB_NO_VNI_EXIST				601
#define DP_ERROR_VM_DEL_LB_UNSUPP_IP				602
#define DP_ERROR_VM_ADD_PFX							650
#define DP_ERROR_VM_ADD_PFX_NO_VM					651
#define DP_ERROR_VM_ADD_PFX_ROUTE					652
#define DP_ERROR_VM_ADD_PFX_VNF_ERR					653
#define DP_ERROR_VM_DEL_PFX							700
#define DP_ERROR_VM_DEL_PFX_NO_VM					701
#define DP_ERROR_CREATE_LB_UNSUPP_IP				750
#define DP_ERROR_CREATE_LB_ERR						751
#define DP_ERROR_DEL_LB_ID_ERR						755
#define DP_ERROR_DEL_LB_BACK_IP_ERR					756
#define DP_ERROR_GET_LB_ID_ERR						760
#define DP_ERROR_GET_LB_BACK_IP_ERR					761


#ifdef __cplusplus
}
#endif
#endif
