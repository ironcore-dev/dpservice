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
#define DP_ERROR_VM_ALREADY_ALLOCATED	109
#define DP_ERROR_VM_CANT_GET_NAME		110
#define DP_ERROR_VM_DEL					150
#define DP_ERROR_VM_DEL_VM_NOT_FND		151
#define DP_ERROR_VM_GET_VM_NOT_FND		171
#define DP_ERROR_VM_LIST				200
#define DP_ERROR_VM_ADD_RT				250
#define DP_ERROR_VM_ADD_RT_FAIL4		251
#define DP_ERROR_VM_ADD_RT_FAIL6		252
#define DP_ERROR_VM_DEL_RT				300
#define DP_ERROR_VM_ADD_NAT				350
#define DP_ERROR_VM_ADD_NAT_IP_EXISTS	351
#define DP_ERROR_VM_ADD_NAT_ALLOC		352
#define DP_ERROR_VM_ADD_NAT_ADD_KEY		353
#define DP_ERROR_VM_ADD_NAT_ADD_DATA	354
#define DP_ERROR_VM_ADD_DNAT			400
#define DP_ERROR_VM_ADD_DNAT_IP_EXISTS	401
#define DP_ERROR_VM_ADD_DNAT_ALLOC		402
#define DP_ERROR_VM_ADD_DNAT_ADD_KEY	403
#define DP_ERROR_VM_ADD_DNAT_ADD_DATA	404
#define DP_ERROR_VM_DEL_NAT				450
#define DP_ERROR_VM_GET_NAT				500
#define DP_ERROR_VM_GET_NAT_NO_IP_SET	501
#define DP_ERROR_VM_ADD_LB_VIP			550
#define DP_ERROR_VM_ADD_LB_NO_VNI_EXIST	551
#define DP_ERROR_VM_ADD_LB_UNSUPP_IP	552
#define DP_ERROR_VM_DEL_LB_VIP			600
#define DP_ERROR_VM_DEL_LB_NO_VNI_EXIST	601
#define DP_ERROR_VM_DEL_LB_UNSUPP_IP	602
#define DP_ERROR_VM_ADD_PFX				650
#define DP_ERROR_VM_ADD_PFX_NO_VM		651
#define DP_ERROR_VM_ADD_PFX_ROUTE		652
#define DP_ERROR_VM_DEL_PFX				700
#define DP_ERROR_VM_DEL_PFX_NO_VM		701



#ifdef __cplusplus
}
#endif
#endif