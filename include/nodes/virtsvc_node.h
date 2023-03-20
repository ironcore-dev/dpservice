#ifndef __INCLUDE_VIRTSVC_NODE_H__
#define __INCLUDE_VIRTSVC_NODE_H__

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int virtsvc_node_append_tx(uint16_t port_id, const char *tx_node_name);

#ifdef __cplusplus
}
#endif
#endif
