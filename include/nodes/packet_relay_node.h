#ifndef __INCLUDE_PACKET_RELAY_NODE_H
#define __INCLUDE_PACKET_RELAY_NODE_H

#include "dpdk_layer.h"

#ifdef __cplusplus
extern "C" {
#endif

	enum
	{
		PACKET_RELAY_NEXT_DROP,
		PACKET_RELAY_NEXT_OVERLAY_SWITCH,
		PACKET_RELAY_NEXT_MAX
	};

	struct packet_relay_node_ctx
	{
		uint16_t next;
	};

	struct packet_relay_node_main
	{
		uint16_t next_index[DP_MAX_PORTS];
	};


#ifdef __cplusplus
}
#endif
#endif /* __INCLUDE_PACKET_RELAY_NODE_H */
