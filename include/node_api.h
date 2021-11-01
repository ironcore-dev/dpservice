#ifndef __PUBLIC_API_H__
#define __PUBLIC_API_H__

#include <rte_common.h>
#include <rte_flow.h>

#ifdef __cplusplus
extern "C" {
#endif

struct dp_flow {
	struct rte_flow_attr	attr;
	struct rte_flow_item	pattern[5];
	struct rte_flow_action	action[5];
	int						pattern_cnt;
	int						action_cnt;
	int 					valid;
};

struct dp_mbuf_priv1 {
	struct dp_flow *flow_ptr;
};

struct rx_node_config
{
	uint16_t port_id;
	uint16_t queue_id;
};

int config_rx_node(struct rx_node_config* cfg);

#ifdef __cplusplus
}
#endif

#endif
