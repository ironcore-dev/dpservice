#ifndef __INCLUDE_IPV6_ENCAP_NODE_H__
#define __INCLUDE_IPV6_ENCAP_NODE_H__

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int ipv6_encap_node_append_pf_tx(uint16_t port_id, const char *tx_node_name);

#ifdef __cplusplus
}
#endif
#endif
