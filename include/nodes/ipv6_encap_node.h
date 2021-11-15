#ifndef __INCLUDE_IPV6_ENCAP_NODE_PRIV_H__
#define __INCLUDE_IPV6_ENCAP_NODE_PRIV_H__

#include "dpdk_layer.h"

#ifdef __cplusplus
extern "C" {
#endif

enum
{
	IPV6_ENCAP_NEXT_DROP,
	IPV6_ENCAP_NEXT_MAX
};

struct ipv6_encap_node_ctx
{
	uint16_t next;
};

struct ipv6_encap_node_main {
	uint16_t next_index[DP_MAX_PORTS];
};

struct rte_node_register *ipv6_encap_node_get(void);
int ipv6_encap_set_next(uint16_t port_id, uint16_t next_index);
#ifdef __cplusplus
}
#endif
#endif