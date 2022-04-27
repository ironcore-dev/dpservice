#ifndef __INCLUDE_IPIP_TUNNEL_NODE_H
#define __INCLUDE_IPIP_TUNNEL_NODE_H

#include "dpdk_layer.h"
#include "rte_flow/dp_rte_flow.h"

#ifdef __cplusplus
extern "C"
{
#endif

	enum
	{
		IPIP_TUNNEL_NEXT_DROP,
		IPIP_TUNNEL_NEXT_IPV6_ENCAP,
		IPIP_TUNNEL_NEXT_IPV4_LOOKUP,
		IPIP_TUNNEL_NEXT_IPV6_LOOKUP,
		IPIP_TUNNEL_NEXT_MAX
	};

	struct ipip_tunnel_node_ctx
	{
		uint16_t next;
	};

	struct ipip_tunnel_node_main
	{
		uint16_t next_index[DP_MAX_PORTS];
	};

	struct rte_node_register *ipip_tunnel_node_get(void);
	int ipip_tunnel_set_next(uint16_t port_id, uint16_t next_index);

#ifdef __cplusplus
}
#endif

#endif /* __INCLUDE_IPIP_TUNNEL_NODE_H */
