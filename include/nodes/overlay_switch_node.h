#ifndef __INCLUDE_OVERLAY_SWITCH_NODE_H
#define __INCLUDE_OVERLAY_SWITCH_NODE_H


#include "dpdk_layer.h"
#include "dp_rte_flow.h"

#ifdef __cplusplus
extern "C" {
#endif

enum
{
	OVERLAY_SWITCH_NEXT_DROP,
	OVERLAY_SWITCH_NEXT_GENEVE,
    OVERLAY_SWITCH_NEXT_IPIP,
	OVERLAY_SWITCH_NEXT_SRV6_ENCAP,
    OVERLAY_SWITCH_NEXT_SRV6_DECAP,
    OVERLAY_SWITCH_NEXT_IPV6_LOOKUP,
	OVERLAY_SWITCH_NEXT_MAX
};

struct overlay_switch_node_ctx
{
	uint16_t next;
};

struct overlay_switch_node_main {
	uint16_t next_index[DP_MAX_PORTS];
};

struct rte_node_register *overlay_switch_node_get(void);
int overlay_switch_set_next(uint16_t port_id, uint16_t next_index);

#ifdef __cplusplus
}
#endif


#endif /* __INCLUDE_OVERLAY_SWITCH_NODE_H */
