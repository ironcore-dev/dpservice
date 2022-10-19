#ifndef __INCLUDE_DNAT_NODE_H__
#define __INCLUDE_DNAT_NODE_H__

#include "dpdk_layer.h"

#ifdef __cplusplus
extern "C" {
#endif

enum
{
	DNAT_NEXT_IPV4_LOOKUP,
	DNAT_NEXT_PACKET_RELAY,
	DNAT_NEXT_DROP,
	DNAT_NEXT_MAX
};


struct dnat_node_ctx
{
	uint16_t next;
};

#ifdef __cplusplus
}
#endif
#endif