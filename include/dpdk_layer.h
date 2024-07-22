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
#ifdef ENABLE_PF1_PROXY
#define DP_MAX_PORTS    (DP_MAX_PF_PORTS + DP_MAX_VF_PORTS + 1)
#else
#define DP_MAX_PORTS    (DP_MAX_PF_PORTS + DP_MAX_VF_PORTS)
#endif

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

// 40Gb/s with 1500B packets means ~9M packets/s
// assuming 0.1s delay in processing means ~900k mbufs needed
#ifdef ENABLE_PYTEST
#define DP_MBUF_POOL_SIZE	(50*1024)
#else
#define DP_MBUF_POOL_SIZE	(900*1024)
#endif

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
