#ifndef _DPDK_LAYER_H_
#define _DPDK_LAYER_H_

#include <rte_memory.h>
#include <rte_launch.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_debug.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_net.h>
#include <rte_graph.h>
#include <rte_node_eth_api.h>
#include <rte_graph_worker.h>

#include <signal.h>

#include "dp_port.h"

#ifdef __cplusplus
extern "C" {
#endif
#define DP_MAX_PF_PORT		2
#define DP_MAX_VF_PRO_PORT	4
#define DP_MAX_PORTS		DP_MAX_PF_PORT * DP_MAX_VF_PRO_PORT
#define DP_NR_RX_QUEUES		1
#define DP_NR_TX_QUEUES		2
#define MEMPOOL_CACHE_SIZE	256
#define DP_NB_SOCKETS		1

#define NB_MBUF(nports)                  \
	RTE_MAX((2 * 1 * 1024 +              \
		 2 * 1 * RTE_GRAPH_BURST_SIZE +  \
		 2 * 1 * 1024 +                  \
		 1 * MEMPOOL_CACHE_SIZE), 29184u)

struct dp_dpdk_layer {
	struct rte_mempool				*rte_mempool;
	struct dp_port					*ports[DP_MAX_PORTS];
	struct rte_node_ethdev_config 	ethdev_conf[DP_MAX_PORTS];
	int								dp_port_cnt;
	uint16_t						nr_rx_queues;
	uint16_t						nr_tx_queues;
	char							graph_name[RTE_GRAPH_NAMESIZE];
	struct							rte_graph *graph;
	rte_graph_t 					graph_id;
};

struct dp_port_ext;

/* Functions for internal processing */
int dp_dpdk_init(int argc, char **argv);
int dp_dpdk_main_loop();
void dp_dpdk_exit();

/* Functions for the control plane */
int dp_prepare(struct dp_port_ext *ports, int port_count);
int dp_allocate_vf(int port_id);
int dp_configure_vf(int port_id);

#ifdef __cplusplus
}
#endif
#endif /* _DP_SERVICE_H_ */
