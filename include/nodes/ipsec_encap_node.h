// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#ifndef __INCLUDE_IPSEC_ENCAP_NODE_H__
#define __INCLUDE_IPSEC_ENCAP_NODE_H__

#include <rte_common.h>

#ifdef __cplusplus
extern "C" {
#endif

int ipsec_encap_node_append_pf_tx(uint16_t port_id, const char *tx_node_name);

#ifdef __cplusplus
}
#endif

#endif
