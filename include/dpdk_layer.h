// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#ifndef _DPDK_LAYER_H_
#define _DPDK_LAYER_H_

#include <stdint.h>
#include <rte_mempool.h>
#include <rte_ring.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DP_MAX_PF_PORTS 2
#define DP_MAX_VF_PORTS 126
#define DP_MAX_PORTS    (DP_MAX_PF_PORTS + DP_MAX_VF_PORTS)

#define DP_NR_STD_RX_QUEUES		1
#define DP_NR_STD_TX_QUEUES		1
#define DP_NR_PF_HAIRPIN_RX_TX_QUEUES	1
#define DP_NR_RESERVED_RX_QUEUES	(DP_NR_STD_RX_QUEUES + \
					 DP_NR_PF_HAIRPIN_RX_TX_QUEUES)
#define DP_NR_RESERVED_TX_QUEUES	(DP_NR_STD_TX_QUEUES + \
					 DP_NR_PF_HAIRPIN_RX_TX_QUEUES)

#define DP_NR_VF_HAIRPIN_RX_TX_QUEUES	1
#define DP_MEMPOOL_CACHE_SIZE	256
#define DP_NB_SOCKETS		2
#define DP_INTERNAL_Q_SIZE	32
#define DP_GRPC_Q_SIZE		64
#define DP_GRPC_REPLY_ARR_SIZE	((DP_GRPC_Q_SIZE / 4) * 3)
// there are three periodic messages (ARP, ND, ND-RA) that could be sent at once
#define DP_PERIODIC_Q_SIZE	(DP_MAX_PORTS * 3)

// While dpservice is processing RTE_GRAPH_BURST_SIZE, the NIC will store packets here
// Seen recommendations to keep this at 2*RTE_GRAPH_BURST_SIZE or 4*RTE_GRAPH_BURST_SIZE
#define DP_RX_QUEUE_SIZE (4 * RTE_GRAPH_BURST_SIZE)
// Seen this recommended to be bigger than Rx because multiple Rx streams share the same Tx
// in our case we are only using one worker thread, so the original thought was that there is no concurrent Tx
// however in practice, having this less than 8xRx leads to tx_node transmission errors
#define DP_TX_QUEUE_SIZE (8 * DP_RX_QUEUE_SIZE)

#ifdef ENABLE_PYTEST
#define DP_MBUF_POOL_SIZE	(50*1024)
#else
// packet pool needs to be able to hold all packets from all port Rx queues
// (as requested in the configure stage via DP_RX_QUEUE_SIZE)
// then also all packets in a burst can allocate a chunk - RTE_GRAPH_BURST_SIZE
// then there are service queues/periodic/grpc/...
// thus a headroom of 4k should be OK
#define DP_MBUF_POOL_HEADROOM 4096
#define DP_MBUF_POOL_SIZE	((DP_NR_STD_RX_QUEUES * DP_RX_QUEUE_SIZE) * DP_MAX_PORTS + DP_MBUF_POOL_HEADROOM)
#endif

// max Ether MTU 1500 + frame header 14 + frame footer 4 + IPv6 tunnel header 40
#define DP_MBUF_BUF_SIZE	(1558 + RTE_PKTMBUF_HEADROOM)

struct dp_dpdk_layer {
	struct rte_mempool	*rte_mempool;
	struct rte_ring		*grpc_tx_queue;
	struct rte_ring		*grpc_rx_queue;
	struct rte_ring		*periodic_msg_queue;
	struct rte_ring		*monitoring_rx_queue;
	int					num_of_vfs;
};

int dp_dpdk_layer_init(void);
int dp_dpdk_main_loop(void);
void dp_dpdk_layer_free(void);

void dp_force_quit(void);

struct dp_dpdk_layer *get_dpdk_layer(void);

#ifdef __cplusplus
}
#endif
#endif
