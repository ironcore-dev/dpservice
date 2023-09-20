#ifndef _DPDK_LAYER_H_
#define _DPDK_LAYER_H_

#include <stdint.h>
#include <rte_mempool.h>
#include <rte_ring.h>

#include "dp_port.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DP_NR_STD_RX_QUEUES		1
#define DP_NR_STD_TX_QUEUES		1
#define DP_NR_PF_HAIRPIN_RX_TX_QUEUES	1
#define DP_NR_RESERVED_RX_QUEUES	(DP_NR_STD_RX_QUEUES + \
					 DP_NR_PF_HAIRPIN_RX_TX_QUEUES)
#define DP_NR_RESERVED_TX_QUEUES	(DP_NR_STD_TX_QUEUES + \
					 DP_NR_PF_HAIRPIN_RX_TX_QUEUES)

#define DP_NR_VF_HAIRPIN_RX_TX_QUEUES	1
#define MEMPOOL_CACHE_SIZE	256
#define DP_NB_SOCKETS		2
#define DP_INTERNAL_Q_SIZE	32
#define DP_GRPC_REPLY_ARR_SIZE	((DP_INTERNAL_Q_SIZE / 4) * 3)

#define NB_MBUF(nports)                  \
	RTE_MAX((2 * 1 * 1024 +              \
		 2 * 1 * RTE_GRAPH_BURST_SIZE +  \
		 2 * 1 * 1024 +                  \
		 1 * MEMPOOL_CACHE_SIZE), 29184u)

struct dp_dpdk_layer {
	struct rte_mempool	*rte_mempool;
	struct rte_ring		*grpc_tx_queue;
	struct rte_ring		*grpc_rx_queue;
	struct rte_ring		*periodic_msg_queue;
	struct rte_ring		*monitoring_rx_queue;
	int					num_of_vfs;
};

struct underlay_conf {
	uint8_t service_ul_ip[16];
};

int dp_dpdk_layer_init(void);
int dp_dpdk_main_loop(void);
void dp_dpdk_layer_free(void);

void dp_force_quit(void);

void set_underlay_conf(struct underlay_conf *u_conf);
struct underlay_conf *get_underlay_conf(void);
struct dp_dpdk_layer *get_dpdk_layer(void);

#ifdef __cplusplus
}
#endif
#endif
