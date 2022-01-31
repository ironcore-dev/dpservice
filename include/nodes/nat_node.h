
#ifndef __INCLUDE_NAT_NODE_H__
#define __INCLUDE_NAT_NODE_H__

#include "dpdk_layer.h"

#ifdef __cplusplus
extern "C" {
#endif

enum
{
	NAT_NEXT_L2_DECAP,
	NAT_NEXT_FIREWALL,
	NAT_NEXT_DROP,
	NAT_NEXT_MAX
};


struct nat_node_ctx
{
	uint16_t next;
};

#ifdef __cplusplus
}
#endif
#endif