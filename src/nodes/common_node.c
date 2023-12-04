// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#include "nodes/common_node.h"
#include "dp_error.h"
#include "dp_log.h"

int dp_node_append_tx(struct rte_node_register *node,
					  uint16_t next_tx_indices[DP_MAX_PORTS],
					  uint16_t port_id,
					  const char *tx_node_name)
{
	const char *append_array[] = { tx_node_name };
	rte_edge_t count;

	if (port_id >= DP_MAX_PORTS) {
		DPNODE_LOG_ERR(node, "Port id too big", DP_LOG_PORTID(port_id), DP_LOG_MAX(DP_MAX_PORTS));
		return DP_ERROR;
	}

	if (rte_node_edge_update(node->id, RTE_EDGE_ID_INVALID, append_array, 1) != 1) {
		DPNODE_LOG_ERR(node, "Cannot add Tx edge", _DP_LOG_STR("peer_tx_node", tx_node_name));
		return DP_ERROR;
	}

	count = rte_node_edge_count(node->id);
	if (count <= 0) {
		DPNODE_LOG_ERR(node, "No Tx edge added", _DP_LOG_STR("peer_tx_node", tx_node_name));
		return DP_ERROR;
	}

	next_tx_indices[port_id] = count - 1;
	return DP_OK;
}

int dp_node_append_vf_tx(struct rte_node_register *node,
					  uint16_t next_tx_indices[DP_MAX_PORTS],
					  uint16_t port_id,
					  const char *tx_node_name)
{
	struct dp_port *port;

	port = dp_get_port_by_id(port_id);
	if (!port || port->is_pf) {
		DPNODE_LOG_ERR(node, "Node requires a valid virtual port to connect to");
		return DP_ERROR;
	}

	return dp_node_append_tx(node, next_tx_indices, port_id, tx_node_name);
}


int dp_node_append_pf_tx(struct rte_node_register *node,
					  uint16_t next_tx_indices[DP_MAX_PORTS],
					  uint16_t port_id,
					  const char *tx_node_name)
{
	struct dp_port *port;

	port = dp_get_port_by_id(port_id);
	if (!port || !port->is_pf) {
		DPNODE_LOG_ERR(node, "Node requires a valid physical port to connect to");
		return DP_ERROR;
	}

	return dp_node_append_tx(node, next_tx_indices, port_id, tx_node_name);
}
