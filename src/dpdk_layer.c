#include "dpdk_layer.h"
#include "dp_error.h"
#include "dp_graph.h"
#include "dp_log.h"
#include "dp_mbuf_dyn.h"
#include "dp_util.h"
#include "grpc/dp_grpc_thread.h"

static volatile bool force_quit;

static struct dp_dpdk_layer dp_layer;
/*TODO these shouldnt be hardcoded */
static struct underlay_conf gen_conf = {
	.dst_port = 6081,
	.src_port = 6081,
	.rsvd1 = 0,
	.vni = {0},
	.trgt_ip6 = {0},
	.src_ip6 = {0},
	.default_port = 443,
};


static inline int ring_init(const char *name, struct rte_ring **p_ring)
{
	*p_ring = rte_ring_create(name, DP_INTERNAL_Q_SIZE, rte_socket_id(), RING_F_SC_DEQ | RING_F_SP_ENQ);
	if (!*p_ring) {
		DPS_LOG_ERR("Error creating '%s' ring buffer %s", name, dp_strerror(rte_errno));
		return DP_ERROR;
	}
	return DP_OK;
}

static inline void ring_free(struct rte_ring *ring)
{
	rte_ring_free(ring);;
}

/** unsafe - does not do cleanup on failure */
static int dp_dpdk_layer_init_unsafe()
{
	dp_layer.rte_mempool = rte_pktmbuf_pool_create("mbuf_pool", NB_MBUF(DP_MAX_PORTS),
												   MEMPOOL_CACHE_SIZE, DP_MBUF_PRIV_DATA_SIZE,
												   RTE_MBUF_DEFAULT_BUF_SIZE,
												   rte_socket_id());
	if (!dp_layer.rte_mempool) {
		DPS_LOG_ERR("Cannot create mbuf pool %s", dp_strerror(rte_errno));
		return DP_ERROR;
	}

	dp_layer.num_of_vfs = dp_get_num_of_vfs();
	if (DP_FAILED(dp_layer.num_of_vfs))
		return DP_ERROR;

	/* TODO monitoring_rx_queue queue needs to be multiproducer, single consumer */
	if (DP_FAILED(ring_init("grpc_tx_queue", &dp_layer.grpc_tx_queue))
		|| DP_FAILED(ring_init("grpc_rx_queue", &dp_layer.grpc_rx_queue))
		|| DP_FAILED(ring_init("periodic_msg_queue", &dp_layer.periodic_msg_queue))
		|| DP_FAILED(ring_init("monitoring_rx_queue", &dp_layer.monitoring_rx_queue)))
		return DP_ERROR;

	if (DP_FAILED(dp_timers_init()))
		return DP_ERROR;

	force_quit = false;

	return DP_OK;
}

int dp_dpdk_layer_init()
{
	// set all to NULL-equivalent, so free-on-failure is safe
	memset(&dp_layer, 0, sizeof(dp_layer));
	if (DP_FAILED(dp_dpdk_layer_init_unsafe())) {
		dp_dpdk_layer_free();
		return DP_ERROR;
	}
	return DP_OK;
}

void dp_dpdk_layer_free(void)
{
	// all functions are safe to call before init
	dp_timers_free();
	ring_free(dp_layer.monitoring_rx_queue);
	ring_free(dp_layer.periodic_msg_queue);
	ring_free(dp_layer.grpc_rx_queue);
	ring_free(dp_layer.grpc_tx_queue);
	rte_mempool_free(dp_layer.rte_mempool);
}

void dp_force_quit()
{
	DPS_LOG_INFO("Stopping service...");
	force_quit = true;
	dp_grpc_thread_cancel();
}


static int graph_main_loop()
{
	struct rte_graph *graph = dp_graph_get();

	dp_log_set_thread_name("worker");

	while (!force_quit)
		rte_graph_walk(graph);

	return 0;
}


static __rte_always_inline int dp_nanosleep(uint64_t ns)
{
	struct timespec delay;

	if (ns > NS_PER_S) {
		delay.tv_sec = ns / NS_PER_S;
		ns -= delay.tv_sec * NS_PER_S;
	} else
		delay.tv_sec = 0;
	delay.tv_nsec = ns;
	return nanosleep(&delay, NULL);
}

static int main_core_loop(void)
{
	uint64_t cur_cycles;
	uint64_t prev_cycles = 0;
	uint64_t elapsed_cycles;
	uint64_t period_cycles = dp_timers_get_manage_interval_cycles();
	double cycles_per_ns = rte_get_timer_hz() / (double)NS_PER_S;
	int ret = DP_OK;

	while (!force_quit) {
		cur_cycles = rte_get_timer_cycles();
		elapsed_cycles = cur_cycles - prev_cycles;
		if (elapsed_cycles < period_cycles) {
			// rte_delay_us_sleep() is not interruptible by signals
			// (and signal is something that should stop this loop)
			dp_nanosleep((period_cycles - elapsed_cycles) / cycles_per_ns);
			// if wait fails, this effectively becomes busy-wait, which is fine
			continue;
		}
		ret = rte_timer_manage();
		if (DP_FAILED(ret)) {
			DPS_LOG_ERR("Timer manager failed %s", dp_strerror(ret));
			// separate thread, need to stop others
			dp_force_quit();
			break;
		}
		prev_cycles = cur_cycles;
	}

	return ret;
}

int dp_dpdk_main_loop(void)
{
	int ret;

	DPS_LOG_INFO("DPDK main loop started");

	/* Launch per-lcore init on every worker lcore */
	ret = rte_eal_mp_remote_launch(graph_main_loop, NULL, SKIP_MAIN);
	if (DP_FAILED(ret)) {
		DPS_LOG_ERR("Cannot launch lcores %s", dp_strerror(ret));
		// custom threads are already running, stop them
		dp_force_quit();
		return ret;
	}

	/* Launch timer loop on main core */
	return main_core_loop();
}


__rte_always_inline struct underlay_conf *get_underlay_conf()
{
	return &gen_conf;
}

__rte_always_inline void set_underlay_conf(struct underlay_conf *u_conf)
{
	gen_conf = *u_conf;
}


struct dp_dpdk_layer *get_dpdk_layer()
{
	return &dp_layer;
}
