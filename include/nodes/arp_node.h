// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#ifndef __INCLUDE_ARP_NODE_H__
#define __INCLUDE_ARP_NODE_H__

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DP_ARP_REQUEST	1
#define DP_ARP_REPLY	2
#define DP_ARP_HW_ETH	1

int arp_node_append_vf_tx(uint16_t port_id, const char *tx_node_name);

#ifdef __cplusplus
}
#endif
#endif
