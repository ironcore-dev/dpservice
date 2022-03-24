#ifndef __INCLUDE_IPV6_LOOKUP_NODE_PRIV_H__
#define __INCLUDE_IPV6_LOOKUP_NODE_PRIV_H__

#include "dpdk_layer.h"

#ifdef __cplusplus
extern "C" {
#endif

enum
{
	IPV6_LOOKUP_NEXT_DROP,
	IPV6_LOOKUP_NEXT_DHCPV6,
	IPV6_LOOKUP_NEXT_L2_DECAP,
	IPV6_LOOKUP_NEXT_MAX
};

struct ipv6_lookup_node_ctx
{
	uint16_t next;
};

struct ipv6_lookup_node_main {
	uint16_t next_index[DP_MAX_PORTS];
};

struct rte_node_register *ipv6_lookup_node_get(void);
int ipv6_lookup_set_next(uint16_t port_id, uint16_t next_index);
#ifdef __cplusplus
}
#endif
#endif
