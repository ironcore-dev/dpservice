#include "dp_hairpin.h"
#include <rte_ethdev.h>
#include "dp_error.h"
#include "dp_log.h"
#include "dpdk_layer.h"
#include "dp_port.h"


static int setup_hairpin_rx_tx_queues(uint16_t port_id,
									  uint16_t peer_port_id,
									  uint8_t hairpin_queue_id,
									  uint8_t peer_hairpin_queue_id)
{
	int ret;

	struct rte_eth_hairpin_conf hairpin_conf = {
		.peer_count = 1,
		.manual_bind = 1,
		.tx_explicit = 1,
	};
	struct rte_eth_rxq_info rxq_info = {0};
	struct rte_eth_txq_info txq_info = {0};

	hairpin_conf.peers[0].port = peer_port_id;
	hairpin_conf.peers[0].queue = peer_hairpin_queue_id;
	ret = rte_eth_rx_queue_info_get(port_id, 0, &rxq_info);
	if (DP_FAILED(ret)) {
		DPS_LOG_ERR("Cannot get rx queue info", DP_LOG_PORTID(port_id), DP_LOG_RET(ret));
		return DP_ERROR;
	}

	DPS_LOG_DEBUG("Configuring rx-to-tx hairpin",
				  DP_LOG_PORTID(port_id), DP_LOG_PEER_PORTID(peer_port_id),
				  _DP_LOG_UINT("hairpin_queue_id", hairpin_queue_id), _DP_LOG_UINT("hairpin_peer_queue_id", peer_hairpin_queue_id));
	ret = rte_eth_rx_hairpin_queue_setup(port_id, hairpin_queue_id,
										 rxq_info.nb_desc, &hairpin_conf);
	if (DP_FAILED(ret)) {
		DPS_LOG_ERR("Cannot configure hairpin rx->tx queue",
					DP_LOG_PORTID(port_id), DP_LOG_PEER_PORTID(peer_port_id), DP_LOG_RET(ret));
		return DP_ERROR;
	}

	hairpin_conf.peers[0].port = port_id;
	hairpin_conf.peers[0].queue = hairpin_queue_id;
	ret = rte_eth_tx_queue_info_get(peer_port_id, 0, &txq_info);
	if (DP_FAILED(ret)) {
		DPS_LOG_ERR("Cannot get tx queue info", DP_LOG_PORTID(port_id), DP_LOG_RET(ret));
		return DP_ERROR;
	}

	DPS_LOG_DEBUG("Configuring tx-to-rx hairpin",
				  DP_LOG_PEER_PORTID(peer_port_id), DP_LOG_PORTID(port_id),
				  _DP_LOG_UINT("hairpin_peer_queue_id", peer_hairpin_queue_id), _DP_LOG_UINT("hairpin_queue_id", hairpin_queue_id));

	ret = rte_eth_tx_hairpin_queue_setup(peer_port_id, peer_hairpin_queue_id,
										 txq_info.nb_desc, &hairpin_conf);
	if (DP_FAILED(ret)) {
		DPS_LOG_ERR("Cannot configure hairpin tx->rx queue",
					DP_LOG_PEER_PORTID(peer_port_id), DP_LOG_PORTID(port_id), DP_LOG_RET(ret));
		return DP_ERROR;
	}

	return DP_OK;
}

int dp_hairpin_setup(struct dp_port *port)
{

	uint16_t hairpin_queue_id = 0;
	uint16_t peer_hairpin_queue_id = 0;

	hairpin_queue_id = DP_NR_STD_RX_QUEUES;
	if (port->port_type == DP_PORT_VF)
		peer_hairpin_queue_id = DP_NR_RESERVED_TX_QUEUES - 1 + port->peer_pf_hairpin_tx_rx_queue_offset;
	else
		peer_hairpin_queue_id = DP_NR_STD_TX_QUEUES - 1 + port->peer_pf_hairpin_tx_rx_queue_offset;

	if (DP_FAILED(setup_hairpin_rx_tx_queues(port->port_id,
											 port->peer_pf_port_id,
											 hairpin_queue_id,
											 peer_hairpin_queue_id))
	) {
		DPS_LOG_ERR("Failed to setup hairpin rx queue for vf", DP_LOG_PORTID(port->port_id));
		return DP_ERROR;
	}

	// PF's hairpin queue is configured one by one
	if (port->port_type == DP_PORT_VF) {
		if (DP_FAILED(setup_hairpin_rx_tx_queues(port->peer_pf_port_id,
												port->port_id,
												peer_hairpin_queue_id,
												hairpin_queue_id))
		) {
			DPS_LOG_ERR("Failed to setup hairpin tx queue for vf", DP_LOG_PORTID(port->port_id));
			return DP_ERROR;
		}
	}
	return DP_OK;
}

int dp_hairpin_bind(struct dp_port *port)
{
	uint16_t port_id = port->port_id;
	uint16_t peer_pf_port = port->peer_pf_port_id;
	int ret;

	// bind txq of peer_pf_port to rxq of port_id

	DPS_LOG_DEBUG("Trying to bind peer to port", DP_LOG_PEER_PORTID(peer_pf_port), DP_LOG_PORTID(port_id));
	ret = rte_eth_hairpin_bind(peer_pf_port, port_id);
	if (DP_FAILED(ret)) {
		DPS_LOG_ERR("Failed to bind peer to port", DP_LOG_PEER_PORTID(peer_pf_port), DP_LOG_PORTID(port_id), DP_LOG_RET(ret));
		return DP_ERROR;
	}

	DPS_LOG_DEBUG("Trying to bind port to peer", DP_LOG_PORTID(port_id), DP_LOG_PEER_PORTID(peer_pf_port));
	ret = rte_eth_hairpin_bind(port_id, peer_pf_port);
	if (DP_FAILED(ret)) {
		DPS_LOG_ERR("Failed to bind port to peer", DP_LOG_PORTID(port_id), DP_LOG_PEER_PORTID(peer_pf_port), DP_LOG_RET(ret));
		return DP_ERROR;
	}

	return DP_OK;
}
