#ifndef __INCLUDE_SRV6_ENCAP_NODE_H
#define __INCLUDE_SRV6_ENCAP_NODE_H




#include "dpdk_layer.h"

#ifdef __cplusplus
extern "C" {
#endif

enum
{
	SRV6_ENCAP_NEXT_DROP,
	SRV6_ENCAP_NEXT_IPV6_ENCAP,
	SRV6_ENCAP_NEXT_MAX
};

struct srv6_encap_node_ctx
{
	uint16_t next;
};

// struct geneve_encap_node_main {
// 	uint16_t next_index[DP_MAX_PORTS];
// };

struct rte_node_register *srv6_encap_node_get(void);
// int geneve_encap_set_next(uint16_t port_id, uint16_t next_index);


#ifdef __cplusplus
}
#endif

#endif /* __INCLUDE_SRV6_ENCAP_NODE_H */
