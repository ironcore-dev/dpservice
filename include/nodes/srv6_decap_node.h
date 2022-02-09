#ifndef __INCLUDE_SRV6_DECAP_NODE_H
#define __INCLUDE_SRV6_DECAP_NODE_H


#include "dpdk_layer.h"

#ifdef __cplusplus
extern "C" {
#endif

enum
{
	SRV6_DECAP_NEXT_DROP,
	SRV6_DECAP_NEXT_IPV4_LOOKUP,
	SRV6_DECAP_NEXT_IPV6_LOOKUP,
	SRV6_DECAP_NEXT_MAX
};

struct srv6_decap_node_ctx
{
	uint16_t next;
};

struct srv6_decap_node_main {
	uint16_t next_index[DP_MAX_PORTS];
};

struct rte_node_register *srv6_decap_node_get(void);
// int srv6_decap_set_next(uint16_t port_id, uint16_t next_index);
#ifdef __cplusplus
}
#endif


#endif /* __INCLUDE_SRV6_DECAP_NODE_H */
