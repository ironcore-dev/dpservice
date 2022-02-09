#ifndef __INCLUDE_IPV6_DECAP_NODE_PRIV_H__
#define __INCLUDE_IPV6_DECAP_NODE_PRIV_H__

#include "dpdk_layer.h"

#ifdef __cplusplus
extern "C" {
#endif

enum
{
	IPV6_DECAP_NEXT_DROP,
	IPV6_DECAP_NEXT_GENEVE_DECAP,
	IPV6_DECAP_NEXT_SRV6_DECAP,
	IPV6_DECAP_NEXT_MAX
};

struct ipv6_decap_node_ctx
{
	uint16_t next;
};

struct ipv6_decap_node_main {
	uint16_t next_index[DP_MAX_PORTS];
};

struct rte_node_register *ipv6_decap_node_get(void);
int ipv6_decap_set_next(uint16_t port_id, uint16_t next_index);
#ifdef __cplusplus
}
#endif
#endif