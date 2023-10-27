#ifndef __INCLUDE_IPIP_ENCAP_NODE_H__
#define __INCLUDE_IPIP_ENCAP_NODE_H__

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int ipip_encap_node_append_pf_tx(uint16_t port_id, const char *tx_node_name);

#ifdef __cplusplus
}
#endif

#endif
