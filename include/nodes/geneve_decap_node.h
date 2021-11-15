#ifndef __INCLUDE_GENEVE_DECAP_NODE_PRIV_H__
#define __INCLUDE_GENEVE_DECAP_NODE_PRIV_H__

#include "dpdk_layer.h"

#ifdef __cplusplus
extern "C" {
#endif

enum
{
	GENEVE_DECAP_NEXT_DROP,
	GENEVE_DECAP_NEXT_IPV4_LOOKUP,
	GENEVE_DECAP_NEXT_MAX
};

struct geneve_decap_node_ctx
{
	uint16_t next;
};

struct geneve_decap_node_main {
	uint16_t next_index[DP_MAX_PORTS];
};

struct rte_node_register *geneve_decap_node_get(void);
int geneve_decap_set_next(uint16_t port_id, uint16_t next_index);
#ifdef __cplusplus
}
#endif
#endif