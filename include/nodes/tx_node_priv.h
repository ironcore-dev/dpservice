#ifndef __INCLUDE_TX_NODE_PRIV_H__
#define __INCLUDE_TX_NODE_PRIV_H__

#include "dpdk_layer.h"

#ifdef __cplusplus
extern "C" {
#endif

enum
{
	TX_NEXT_DROP,
	TX_NEXT_MAX
};

enum
{
	DP_ROUTE_TO_VM,
	DP_ROUTE_TO_VM_DECAPPED,
	DP_ROUTE_TO_PF_ENCAPPED,
};

struct tx_node_ctx
{
	uint16_t port_id;
	uint16_t queue_id;
	uint16_t next;
};

struct ethdev_tx_node_main {
	uint32_t nodes[DP_MAX_PORTS];
	uint16_t port_ids[DP_MAX_PORTS];
};

struct ethdev_tx_node_main *tx_node_data_get(void);
struct rte_node_register *tx_node_get(void);
#ifdef __cplusplus
}
#endif
#endif