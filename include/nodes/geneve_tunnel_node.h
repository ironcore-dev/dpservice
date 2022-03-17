#ifndef __INCLUDE_GENEVE_TUNNEL_NODE_H
#define __INCLUDE_GENEVE_TUNNEL_NODE_H

#ifdef __cplusplus
extern "C"
{
#endif

#include "dpdk_layer.h"
#include "dp_rte_flow.h"

	enum
	{
		GENEVE_TUNNEL_NEXT_DROP,
		GENEVE_TUNNEL_NEXT_IPV6_ENCAP,
		GENEVE_TUNNEL_NEXT_IPV4_LOOKUP,
		GENEVE_TUNNEL_NEXT_IPV6_LOOKUP,
		GENEVE_TUNNEL_NEXT_MAX
	};

	struct geneve_tunnel_node_ctx
	{
		uint16_t next;
	};

	struct geneve_tunnel_node_main
	{
		uint16_t next_index[DP_MAX_PORTS];
	};

	struct rte_node_register *geneve_tunnel_node_get(void);
	int geneve_tunnel_set_next(uint16_t port_id, uint16_t next_index);

#ifdef __cplusplus
}
#endif

#endif /* __INCLUDE_GENEVE_TUNNEL_NODE_H */
