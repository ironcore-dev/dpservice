
#ifndef __INCLUDE_FIREWALL_NODE_H__
#define __INCLUDE_FIREWALL_NODE_H__

#include "dpdk_layer.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DP_FIREWL_PASS_PACKET 1
#define DP_FIREWL_DROP_PACKET 0

enum
{
	FIREWALL_NEXT_L2_DECAP,
	FIREWALL_NEXT_DROP,
	FIREWALL_NEXT_MAX
};


struct firewall_node_ctx
{
	uint16_t next;
};

#ifdef __cplusplus
}
#endif
#endif