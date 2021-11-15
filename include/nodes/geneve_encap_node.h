#ifndef __INCLUDE_GENEVE_ENCAP_NODE_PRIV_H__
#define __INCLUDE_GENEVE_ENCAP_NODE_PRIV_H__

#include "dpdk_layer.h"

#ifdef __cplusplus
extern "C" {
#endif

enum
{
	GENEVE_ENCAP_NEXT_DROP,
	GENEVE_ENCAP_NEXT_IPV6_ENCAP,
	GENEVE_ENCAP_NEXT_MAX
};

struct geneve_encap_node_ctx
{
	uint16_t next;
};

struct geneve_encap_node_main {
	uint16_t next_index[DP_MAX_PORTS];
};

struct rte_node_register *geneve_encap_node_get(void);
int geneve_encap_set_next(uint16_t port_id, uint16_t next_index);
#ifdef __cplusplus
}
#endif
#endif