#ifndef _DPDK_LAYER_H_
#define _DPDK_LAYER_H_

#include <rte_node_eth_api.h>
#include <rte_graph_worker.h>
#include <rte_timer.h>
#include <rte_cycles.h>

#include "dp_port.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DP_NR_STD_RX_QUEUES		1
#define DP_NR_STD_TX_QUEUES		1
#define DP_NR_VF_HAIRPIN_RX_TX_QUEUES	1
#define MEMPOOL_CACHE_SIZE	256
#define DP_NB_SOCKETS		2
#define DP_INTERNAL_Q_SIZE	32
#define DP_MBUF_ARR_SIZE	((DP_INTERNAL_Q_SIZE / 4) * 3)

#define NB_MBUF(nports)                  \
	RTE_MAX((2 * 1 * 1024 +              \
		 2 * 1 * RTE_GRAPH_BURST_SIZE +  \
		 2 * 1 * 1024 +                  \
		 1 * MEMPOOL_CACHE_SIZE), 29184u)

struct dp_dpdk_layer {
	struct rte_mempool	*rte_mempool;
	char				graph_name[RTE_GRAPH_NAMESIZE];
	struct				rte_graph *graph;
	rte_graph_t			graph_id;
	struct rte_ring		*grpc_tx_queue;
	struct rte_ring		*grpc_rx_queue;
	struct rte_ring		*periodic_msg_queue;
	struct rte_ring		*monitoring_rx_queue;
	int					num_of_vfs;
};

struct underlay_conf {
	uint16_t dst_port;
	uint16_t src_port;
	// TODO(plague) this is not supported anymore, but removal could break it, look into it
	uint8_t vni[3];
	uint8_t rsvd1;
	/* Virtual IP */
	union {
		uint32_t	src_ip4;
		uint8_t		src_ip6[16];
	};
	union {
		uint32_t	trgt_ip4;
		uint8_t		trgt_ip6[16];
	};
	uint16_t default_port;
};

int dp_dpdk_layer_init(void);
int dp_graph_init(void);
int dp_dpdk_main_loop(void);
void dp_dpdk_layer_free(void);

void dp_force_quit();

void set_underlay_conf(struct underlay_conf *u_conf);
struct underlay_conf *get_underlay_conf();
struct dp_dpdk_layer *get_dpdk_layer();

#ifdef __cplusplus
}
#endif
#endif
