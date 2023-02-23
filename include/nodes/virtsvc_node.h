#ifndef __INCLUDE_VIRTSVC_NODE_PRIV_H__
#define __INCLUDE_VIRTSVC_NODE_PRIV_H__

#include "dp_port.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
	VIRTSVC_NEXT_DROP,
	VIRTSVC_NEXT_MAX
};

struct virtsvc_node_main {
	uint16_t next_index[DP_MAX_PORTS];
};

struct rte_node_register *virtsvc_node_get(void);
int virtsvc_set_next(uint16_t port_id, uint16_t next_index);

#ifdef __cplusplus
}
#endif
#endif
