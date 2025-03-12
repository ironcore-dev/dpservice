// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#ifndef __INCLUDE_RX_NODE_H__
#define __INCLUDE_RX_NODE_H__

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

int rx_node_create(uint16_t port_id, uint16_t queue_id);

int rx_node_set_enabled(uint16_t port_id, bool enabled);

void rx_node_start_processing(void);

#ifdef __cplusplus
}
#endif
#endif
