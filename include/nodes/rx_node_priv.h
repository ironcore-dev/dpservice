#ifndef __INCLUDE_RX_NODE_PRIV_H__
#define __INCLUDE_RX_NODE_PRIV_H__

#include "dpdk_layer.h"

#ifdef __cplusplus
extern "C" {
#endif

enum
{
	RX_NEXT_CLS,
	RX_NEXT_MAX
};

struct rx_node_ctx
{
	uint16_t node_id;
	uint16_t port_id;
	uint16_t queue_id;
	uint16_t next;
};

struct rx_node_config
{
	uint16_t node_id;
	uint16_t port_id;
	uint16_t queue_id;
};

struct ethdev_rx_node_main {
	struct rx_node_ctx node_ctx[DP_MAX_PORTS];
};

int config_rx_node(struct rx_node_config* cfg);
struct rte_node_register *rx_node_get(void);
#ifdef __cplusplus
}
#endif
#endif