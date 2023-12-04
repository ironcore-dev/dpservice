// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#ifndef __INCLUDE_DHCPV6_NODE_H__
#define __INCLUDE_DHCPV6_NODE_H__

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int dhcpv6_node_append_vf_tx(uint16_t port_id, const char *tx_node_name);

#ifdef __cplusplus
}
#endif

#endif
