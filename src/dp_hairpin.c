#include "dp_hairpin.h"
#include <rte_ethdev.h>
#include "dp_error.h"
#include "dp_log.h"
#include "dpdk_layer.h"


static int setup_hairpin_rx_tx_queues(uint16_t port_id,
									  uint16_t peer_port_id,
									  uint8_t port_hairpin_rx_q_offset,
									  uint8_t peer_port_hairpin_tx_q_offset)
{
	uint16_t hairpin_queue = DP_NR_STD_RX_QUEUES - 1 + port_hairpin_rx_q_offset;
	uint16_t peer_hairpin_queue = DP_NR_STD_TX_QUEUES - 1 + peer_port_hairpin_tx_q_offset;
	int ret;

	struct rte_eth_hairpin_conf hairpin_conf = {
		.peer_count = 1,
		.manual_bind = 1,
		.tx_explicit = 1,
	};
	struct rte_eth_rxq_info rxq_info = {0};
	struct rte_eth_txq_info txq_info = {0};

	hairpin_conf.peers[0].port = peer_port_id;
	hairpin_conf.peers[0].queue = peer_hairpin_queue;
	ret = rte_eth_rx_queue_info_get(port_id, 0, &rxq_info);
	if (DP_FAILED(ret)) {
		DPS_LOG_ERR("Cannot get rx queue info for port %d %s", port_id, dp_strerror(ret));
		return DP_ERROR;
	}

	DPS_LOG_DEBUG("Configuring hairpin from port %d to port %d, rxq %d to txq %d",
				  port_id, peer_port_id, hairpin_queue, peer_hairpin_queue);
	ret = rte_eth_rx_hairpin_queue_setup(port_id, hairpin_queue,
										 rxq_info.nb_desc, &hairpin_conf);
	if (DP_FAILED(ret)) {
		DPS_LOG_ERR("Cannot configure hairpin rx->tx queue from %d to %d %s", port_id, peer_port_id, dp_strerror(ret));
		return DP_ERROR;
	}

	hairpin_conf.peers[0].port = port_id;
	hairpin_conf.peers[0].queue = hairpin_queue;
	ret = rte_eth_tx_queue_info_get(peer_port_id, 0, &txq_info);
	if (DP_FAILED(ret)) {
		DPS_LOG_ERR("Cannot get tx queue info for port %d %s", port_id, dp_strerror(ret));
		return DP_ERROR;
	}

	DPS_LOG_DEBUG("Configuring hairpin from port %d to port %d, txq %d to rxq %d",
				  peer_port_id, port_id, peer_hairpin_queue, hairpin_queue);
	ret = rte_eth_tx_hairpin_queue_setup(peer_port_id, peer_hairpin_queue,
										 txq_info.nb_desc, &hairpin_conf);
	if (DP_FAILED(ret)) {
		DPS_LOG_ERR("Cannot configure hairpin tx->rx queue from %d to %d %s", peer_port_id, port_id, dp_strerror(ret));
		return DP_ERROR;
	}

	return DP_OK;
}

int dp_hairpin_setup(struct dp_port *port)
{
	if (DP_FAILED(setup_hairpin_rx_tx_queues(port->port_id,
											 port->peer_pf_port_id,
											 1,
											 port->peer_pf_hairpin_tx_rx_queue_offset))
	) {
		DPS_LOG_ERR("Failed to setup hairpin rx queue for vf %d", port->port_id);
		return DP_ERROR;
	}

	if (DP_FAILED(setup_hairpin_rx_tx_queues(port->peer_pf_port_id,
											 port->port_id,
											 port->peer_pf_hairpin_tx_rx_queue_offset,
											 1))
	) {
		DPS_LOG_ERR("Failed to setup hairpin tx queue for vf %d", port->port_id);
		return DP_ERROR;
	}

	return DP_OK;
}

int dp_hairpin_bind(struct dp_port *port)
{
	uint16_t port_id = port->port_id;
	uint16_t peer_pf_port = port->peer_pf_port_id;
	int ret;

	// bind txq of peer_pf_port to rxq of port_id

	DPS_LOG_DEBUG("Trying to bind %d to %d", peer_pf_port, port_id);
	ret = rte_eth_hairpin_bind(peer_pf_port, port_id);
	if (DP_FAILED(ret)) {
		DPS_LOG_ERR("Failed to bind %d to %d %s", peer_pf_port, port_id, dp_strerror(ret));
		return DP_ERROR;
	}

	DPS_LOG_DEBUG("Trying to bind %d to %d", port_id, peer_pf_port);
	ret = rte_eth_hairpin_bind(port_id, peer_pf_port);
	if (DP_FAILED(ret)) {
		DPS_LOG_ERR("Failed to bind %d to %d %s", port_id, peer_pf_port, dp_strerror(ret));
		return DP_ERROR;
	}

	return DP_OK;
}
