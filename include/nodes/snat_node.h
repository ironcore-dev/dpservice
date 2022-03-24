
#ifndef __INCLUDE_SNAT_NODE_H__
#define __INCLUDE_SNAT_NODE_H__

#include "dpdk_layer.h"

#ifdef __cplusplus
extern "C" {
#endif

enum
{
	SNAT_NEXT_FIREWALL,
	SNAT_NEXT_DROP,
	SNAT_NEXT_MAX
};


struct snat_node_ctx
{
	uint16_t next;
};

#ifdef __cplusplus
}
#endif
#endif