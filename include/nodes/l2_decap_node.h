#ifndef __INCLUDE_L2_DECAP_NODE_PRIV_H__
#define __INCLUDE_L2_DECAP_NODE_PRIV_H__

#include "dpdk_layer.h"

#ifdef __cplusplus
extern "C" {
#endif

enum
{
	L2_DECAP_NEXT_DROP,
	L2_DECAP_OVERLAY_SWITCH,
	// L2_DECAP_NEXT_GENEVE_ENCAP,
	// L2_DECAP_NEXT_SRV6_ENCAP,
	L2_DECAP_NEXT_MAX
};

struct l2_decap_node_ctx
{
	uint16_t next;
};

struct l2_decap_node_main {
	uint16_t next_index[DP_MAX_PORTS];
};

struct rte_node_register *l2_decap_node_get(void);
int l2_decap_set_next(uint16_t port_id, uint16_t next_index);
#ifdef __cplusplus
}
#endif
#endif