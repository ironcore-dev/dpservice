#ifndef __INCLUDE_CONNTRACK_NODE_H__
#define __INCLUDE_CONNTRACK_NODE_H__

#include "dpdk_layer.h"

#ifdef __cplusplus
extern "C" {
#endif

enum
{
	CONNTRACK_NEXT_DNAT,
	//CONNTRACK_NEXT_LB,
	CONNTRACK_NEXT_DROP,
	CONNTRACK_NEXT_MAX
};


struct conntrack_node_ctx
{
	uint16_t next;
};

#ifdef __cplusplus
}
#endif
#endif