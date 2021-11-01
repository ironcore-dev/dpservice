#ifndef __INCLUDE_IPV4_LOOKUP_NODE_PRIV_H__
#define __INCLUDE_IPV4_LOOKUP_NODE_PRIV_H__

#include "dpdk_layer.h"

#ifdef __cplusplus
extern "C" {
#endif

enum
{
	IPV4_LOOKUP_NEXT_DROP,
	IPV4_LOOKUP_NEXT_MAX
};

struct ipv4_lookup_node_ctx
{
	uint16_t next;
};

struct ipv4_lookup_node_main {
	uint16_t next_index[DP_MAX_PORTS];
};

struct rte_node_register *ipv4_lookup_node_get(void);
int ipv4_lookup_set_next(uint16_t port_id, uint16_t next_index);
#ifdef __cplusplus
}
#endif
#endif