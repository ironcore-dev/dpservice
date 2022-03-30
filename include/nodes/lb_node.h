#ifndef __INCLUDE_LB_NODE_H__
#define __INCLUDE_LB_NODE_H__

#include "dpdk_layer.h"

#ifdef __cplusplus
extern "C" {
#endif

enum
{
	LB_NEXT_IPV4_LOOKUP,
	LB_NEXT_DNAT,
	LB_NEXT_DROP,
	LB_NEXT_MAX
};


struct lb_node_ctx
{
	uint16_t next;
};

#ifdef __cplusplus
}
#endif
#endif