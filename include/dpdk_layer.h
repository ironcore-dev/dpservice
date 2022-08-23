#ifndef _DPDK_LAYER_H_
#define _DPDK_LAYER_H_

#include <rte_node_eth_api.h>
#include <rte_graph_worker.h>
#include <rte_timer.h>
#include <rte_cycles.h>

#include <signal.h>
#include <pthread.h>

#include "dp_port.h"

#ifdef __cplusplus
extern "C" {
#endif
#define DP_MAX_PF_PORT		2
#define DP_MAX_VF_PRO_PORT	32
#define DP_ACTIVE_VF_PORT	4
#define DP_MAX_PORTS		DP_MAX_PF_PORT * DP_MAX_VF_PRO_PORT
#define DP_NR_STD_RX_QUEUES		1
#define DP_NR_STD_TX_QUEUES		1
#define DP_NR_VF_HAIRPIN_RX_TX_QUEUES	1
#define MEMPOOL_CACHE_SIZE	256
#define DP_NB_SOCKETS		2
#define DP_INTERNAL_Q_SIZE	32
#define DP_MBUF_ARR_SIZE	(DP_INTERNAL_Q_SIZE / 4) * 3

#define NB_MBUF(nports)                  \
	RTE_MAX((2 * 1 * 1024 +              \
		 2 * 1 * RTE_GRAPH_BURST_SIZE +  \
		 2 * 1 * 1024 +                  \
		 1 * MEMPOOL_CACHE_SIZE), 29184u)

struct dp_dpdk_layer {
	struct rte_mempool				*rte_mempool;
	struct dp_port					*ports[DP_MAX_PORTS];
	struct rte_node_ethdev_config	ethdev_conf[DP_MAX_PORTS];
	int								dp_port_cnt;
	uint16_t						nr_std_rx_queues;
	uint16_t						nr_std_tx_queues;
	uint16_t						nr_pf_hairpin_rx_tx_queues;
	uint16_t						nr_vf_hairpin_rx_tx_queues;
	char							graph_name[RTE_GRAPH_NAMESIZE];
	struct							rte_graph *graph;
	rte_graph_t					graph_id;
	struct rte_ring					*grpc_tx_queue;
	struct rte_ring					*grpc_rx_queue;
	struct rte_ring					*periodic_msg_queue;
	struct rte_ring					*monitoring_rx_queue;
};

struct underlay_conf {
	uint16_t dst_port;
	uint16_t src_port;
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

/* Functions for internal processing */
int dp_dpdk_init(int argc, char **argv);
int dp_init_graph(void);
int dp_dpdk_main_loop(void);
void dp_dpdk_exit(void);

/* Functions for the control plane */
int dp_init_interface(struct dp_port_ext *port, dp_port_type type);
void dp_start_interface(struct dp_port_ext *port_ext, int portid, dp_port_type type);
void dp_stop_interface(int portid, dp_port_type type);

void set_underlay_conf(struct underlay_conf *u_conf);
struct underlay_conf *get_underlay_conf();
struct dp_dpdk_layer *get_dpdk_layer();
pthread_t *dp_get_ctrl_thread_id();

int hairpin_vfs_to_pf(void);
int hairpin_ports_bind(uint16_t tx_port_id, uint16_t rx_port_id);
int hairpin_ports_bind_all(uint16_t port_id);
int bind_vf_with_peer_pf_port(uint16_t port_id);
uint16_t get_pf_hairpin_rx_queue(uint16_t port_id);

#ifdef __cplusplus
}
#endif
#endif /* _DP_SERVICE_H_ */
