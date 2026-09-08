// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#ifndef __INCLUDE_IPIP_ENCAP_NODE_H__
#define __INCLUDE_IPIP_ENCAP_NODE_H__

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int ipip_encap_node_append_pf_tx(uint16_t port_id, const char *tx_node_name);

// Only called when dpservice runs with the IPsec capability. Packets from an encrypting
// interface take this edge instead of the Tx one above.
int ipip_encap_node_append_pf_ipsec(uint16_t port_id, const char *ipsec_node_name);

#ifdef __cplusplus
}
#endif

#endif
