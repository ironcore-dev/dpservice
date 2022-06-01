#ifndef __INCLUDE_ARP_NODE_PRIV_H__
#define __INCLUDE_ARP_NODE_PRIV_H__

#include "dpdk_layer.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DP_ARP_REQUEST	1
#define DP_ARP_REPLY	2
#define DP_ARP_HW_ETH	1

enum
{
	ARP_NEXT_DROP,
	ARP_NEXT_MAX
};

struct arp_node_ctx
{
	uint16_t next;
};

struct arp_node_main {
	uint16_t next_index[DP_MAX_PORTS];
};

struct rte_node_register *arp_node_get(void);
int arp_set_next(uint16_t port_id, uint16_t next_index);
#ifdef __cplusplus
}
#endif
#endif