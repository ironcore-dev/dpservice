#include <unistd.h>
#include "rte_malloc.h"
#include "dpdk_layer.h"
#include "dp_mbuf_dyn.h"
#include "node_api.h"
#include "dp_lpm.h"
#include "dp_netlink.h"
#include "dp_util.h"
#include "dp_periodic_msg.h"
#include "nodes/tx_node_priv.h"
#include "nodes/rx_node_priv.h"
#include "nodes/arp_node_priv.h"
#include "nodes/ipv6_nd_node.h"
#include "nodes/dhcp_node.h"
#include "nodes/dhcpv6_node.h"
#include "nodes/l2_decap_node.h"
#include "nodes/ipv6_encap_node.h"
#include "nodes/rx_periodic_node.h"
#include "nodes/ipv6_lookup_node.h"
#include "nodes/ipip_tunnel_node.h"
#include "nodes/packet_relay_node.h"
#ifdef ENABLE_VIRTSVC
#	include "nodes/virtsvc_node.h"
#endif
#include "monitoring/dp_monitoring.h"
#include "dp_port.h"
#include "dp_error.h"
#include "dp_log.h"
#include "dp_timers.h"

#define STATS_SLEEP 1

static volatile bool force_quit;

static const char * const default_patterns[] = {
	"rx-*",
	"rx-periodic",
	"cls",
	"arp",
	"ipv6_nd",
	"ipv4_lookup",
	"ipv6_lookup",
	"dhcp",
	"dhcpv6",
	"conntrack",
	"dnat",
	"firewall",
	"snat",
	"l2_decap",
	"ipv6_encap",
	"geneve_tunnel",
	"ipip_tunnel",
	"overlay_switch",
	"packet_relay",
	"tx-*",
	"drop",
};

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
												   MEMPOOL_CACHE_SIZE, RTE_CACHE_LINE_SIZE + 32,
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
}


static int graph_main_loop()
{
	struct rte_graph *graph = dp_layer.graph;

	dp_log_set_thread_name("worker");

	while (!force_quit)
		rte_graph_walk(graph);

	return 0;
}

static inline struct rte_graph_cluster_stats *create_stats()
{
	static const char *patterns[] = { "worker_*" };
	struct rte_graph_cluster_stats_param s_param = {
		.socket_id = SOCKET_ID_ANY,
		.fn = NULL,
		.f = stdout,
		.nb_graph_patterns = 1,
		.graph_patterns = patterns,
	};
	struct rte_graph_cluster_stats *stats;

	stats = rte_graph_cluster_stats_create(&s_param);
	if (!stats)
		DPS_LOG_ERR("Unable to create cluster stats %s", dp_strerror(rte_errno));

	return stats;
}

static inline void print_stats(struct rte_graph_cluster_stats *stats)
{
	static const char caret_top_left[] = {27, '[', '1', ';', '1', 'H', '\0'};
	static const char clear_screen[] = {27, '[', '2', 'J', '\0'};

	printf("%s%s", clear_screen, caret_top_left);
	// this actually prints using a function specified in create_stats()
	rte_graph_cluster_stats_get(stats, 0);
}

static inline void free_stats(struct rte_graph_cluster_stats *stats)
{
	rte_graph_cluster_stats_destroy(stats);
}

static int main_core_loop(void)
{
	uint64_t cur_tsc;
	uint64_t prev_tsc = 0;
	uint64_t periodicity = dp_get_timer_manage_interval();
	int ret = DP_OK;
	struct rte_graph_cluster_stats *stats = NULL;

	if (dp_conf_is_stats_enabled() && rte_graph_has_stats_feature()) {
		stats = create_stats();
		if (!stats)
			return DP_ERROR;
	}

	while (!force_quit) {
		cur_tsc = rte_get_timer_cycles();
		if ((cur_tsc - prev_tsc) > periodicity) {
			ret = rte_timer_manage();
			if (DP_FAILED(ret)) {
				DPS_LOG_ERR("Timer manager failed %s", dp_strerror(ret));
				break;
			}
			prev_tsc = cur_tsc;
		}

		if (stats) {
			print_stats(stats);
			sleep(STATS_SLEEP);
		}
	}

	if (stats)
		free_stats(stats);

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
		return ret;
	}

	/* Launch timer loop on main core */
	return main_core_loop();
}


static inline int dp_graph_export(const char graph_name[RTE_GRAPH_NAMESIZE])
{
	int ret;
	FILE *f;
	char fname[RTE_GRAPH_NAMESIZE + 5];  // + ".dot\0"

	if (snprintf(fname, sizeof(fname), "%s.dot", graph_name) >= sizeof(fname)) {
		DPS_LOG_ERR("Cannot export graph, name too long");
		return DP_ERROR;
	}
	f = fopen(fname, "w");
	if (!f) {
		DPS_LOG_ERR("Cannot open graph export file for writing %s", dp_strerror(errno));
		return DP_ERROR;
	}
	ret = rte_graph_export(dp_layer.graph_name, f);
	if (DP_FAILED(ret))
		DPS_LOG_ERR("rte_graph_export() failed %s", dp_strerror(ret));
	fclose(f);
	return ret;
}

int dp_graph_init(void)
{
	struct rte_node_register *rx_node, *tx_node, *arp_node, *ipv6_encap_node;
	struct rte_node_register *dhcp_node, *l2_decap_node, *ipv6_nd_node;
	struct rte_node_register *dhcpv6_node, *rx_periodic_node;
#ifdef ENABLE_VIRTSVC
	struct rte_node_register *virtsvc_node;
#endif
	struct ethdev_tx_node_main *tx_node_data;
	char name[RTE_NODE_NAMESIZE];
	const char *next_nodes = name;
	struct rx_node_config rx_cfg;
	struct rx_periodic_node_config rx_periodic_cfg;
	int ret, id;
	struct rte_graph_param graph_conf = {0};
	const char **node_patterns;
	int nb_patterns;
	uint32_t lcore_id;
	struct dp_ports *ports = get_dp_ports();

	/* Graph Initialization */
	nb_patterns = RTE_DIM(default_patterns);
	// TODO(plague): this constant should be DP_NR_STD_RX_QUEUES, but needs testing as it is smaller (1)!
	node_patterns = malloc((2 + nb_patterns) * sizeof(*node_patterns));
	// TODO(plague): thre's no free(), dp_graph_free() needed?
	if (!node_patterns) {
		DPS_LOG_ERR("Cannot allocate graph node patterns");
		return DP_ERROR;
	}
	memcpy(node_patterns, default_patterns, nb_patterns * sizeof(*node_patterns));
	graph_conf.node_patterns = node_patterns;

	/* Graph Configuration */
	tx_node_data = tx_node_data_get();
	tx_node = tx_node_get();
	rx_node = rx_node_get();
	arp_node = arp_node_get();
	ipv6_nd_node = ipv6_nd_node_get();
	l2_decap_node = l2_decap_node_get();
	ipv6_encap_node = ipv6_encap_node_get();
	dhcp_node = dhcp_node_get();
	dhcpv6_node = dhcpv6_node_get();
	rx_periodic_node = rx_periodic_node_get();
#ifdef ENABLE_VIRTSVC
	virtsvc_node = virtsvc_node_get();
#endif

	/* it is not really needed to init queues in this way, and init can be done within node's init function */
	rx_periodic_cfg.periodic_msg_queue = dp_layer.periodic_msg_queue;
	rx_periodic_cfg.grpc_tx = dp_layer.grpc_tx_queue;
	rx_periodic_cfg.grpc_rx = dp_layer.grpc_rx_queue;
	rx_periodic_cfg.monitoring_rx = dp_layer.monitoring_rx_queue;
	// TODO(plague): the whole DP node api needs work, either this will be void or properly check
	// (this will apply on many places below)
	ret = config_rx_periodic_node(&rx_periodic_cfg);

	DP_FOREACH_PORT(ports, port) {
		// TODO(plague): just create a function for the loop?
		snprintf(name, sizeof(name), "%u-%u", port->port_id, 0);
		/* Clone a new rx node with same edges as parent */
		id = rte_node_clone(rx_node->id, name);
		if (id == RTE_NODE_ID_INVALID) {
			DPS_LOG_ERR("Cannot clone rx node %s", dp_strerror(rte_errno));
			return DP_ERROR;
		}
		rx_cfg.port_id = port->port_id;
		rx_cfg.queue_id = 0;
		rx_cfg.node_id = id;
		// TODO(plague): DP node api
		ret = config_rx_node(&rx_cfg);

		snprintf(name, sizeof(name), "%u", port->port_id);
		id = rte_node_clone(tx_node->id, name);
		if (id == RTE_NODE_ID_INVALID) {
			DPS_LOG_ERR("Cannot clone rx node %s", dp_strerror(rte_errno));
			return DP_ERROR;
		}
		tx_node_data->nodes[port->port_id] = id;
		tx_node_data->port_ids[port->port_id] = port->port_id;

		snprintf(name, sizeof(name), "tx-%u", port->port_id);
		if (port->port_type == DP_PORT_VF) {
			// TODO(plague): all these can fail with RTE_EDGE_ID_INVALID and set rte_errno
			rte_node_edge_update(arp_node->id, RTE_EDGE_ID_INVALID, &next_nodes, 1);
			// TODO(plague): maybe rework DP node api to do each in one call
			// TODO(plague): update retval checks
			ret = arp_set_next(port->port_id, rte_node_edge_count(arp_node->id) - 1);
			if (ret < 0) {
				DPS_LOG_ERR("Node set next failed %s", dp_strerror(ret));
				return ret;
			}
			rte_node_edge_update(rx_periodic_node->id, RTE_EDGE_ID_INVALID, &next_nodes, 1);
			ret = rx_periodic_set_next(port->port_id, rte_node_edge_count(rx_periodic_node->id) - 1);
			if (ret < 0) {
				DPS_LOG_ERR("Node set next failed %s", dp_strerror(ret));
				return ret;
			}
			rte_node_edge_update(ipv6_nd_node->id, RTE_EDGE_ID_INVALID, &next_nodes, 1);
			ret = ipv6_nd_set_next(port->port_id, rte_node_edge_count(ipv6_nd_node->id) - 1);
			if (ret < 0) {
				DPS_LOG_ERR("Node set next failed %s", dp_strerror(ret));
				return ret;
			}
			rte_node_edge_update(dhcp_node->id, RTE_EDGE_ID_INVALID, &next_nodes, 1);
			ret = dhcp_set_next(port->port_id, rte_node_edge_count(dhcp_node->id) - 1);
			if (ret < 0) {
				DPS_LOG_ERR("Node set next failed %s", dp_strerror(ret));
				return ret;
			}
			rte_node_edge_update(dhcpv6_node->id, RTE_EDGE_ID_INVALID, &next_nodes, 1);
			ret = dhcpv6_set_next(port->port_id, rte_node_edge_count(dhcpv6_node->id) - 1);
			if (ret < 0) {
				DPS_LOG_ERR("Node set next failed %s", dp_strerror(ret));
				return ret;
			}
			rte_node_edge_update(l2_decap_node->id, RTE_EDGE_ID_INVALID, &next_nodes, 1);
			ret = l2_decap_set_next(port->port_id, rte_node_edge_count(l2_decap_node->id) - 1);
			if (ret < 0) {
				DPS_LOG_ERR("Node set next failed %s", dp_strerror(ret));
				return ret;
			}
#ifdef ENABLE_VIRTSVC
			rte_node_edge_update(virtsvc_node->id, RTE_EDGE_ID_INVALID, &next_nodes, 1);
			ret = virtsvc_set_next(port->port_id, rte_node_edge_count(virtsvc_node->id) - 1);
			if (ret < 0) {
				DPS_LOG_ERR("Node set next failed %s", dp_strerror(ret));
				return ret;
			}
#endif
		}

		if (port->port_type == DP_PORT_PF) {
			rte_node_edge_update(ipv6_encap_node->id, RTE_EDGE_ID_INVALID, &next_nodes, 1);
			ret = ipv6_encap_set_next(port->port_id, rte_node_edge_count(ipv6_encap_node->id) - 1);
			if (ret < 0) {
				DPS_LOG_ERR("Node set next failed %s", dp_strerror(ret));
				return ret;
			}
#ifdef ENABLE_VIRTSVC
			rte_node_edge_update(virtsvc_node->id, RTE_EDGE_ID_INVALID, &next_nodes, 1);
			ret = virtsvc_set_next(port->port_id, rte_node_edge_count(virtsvc_node->id) - 1);
			if (ret < 0) {
				DPS_LOG_ERR("Node set next failed %s", dp_strerror(ret));
				return ret;
			}
#endif
		}
	}
	for (lcore_id = 1; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		// TODO(plague): just create a function for the loop
		rte_graph_t graph_id;

		if (!rte_lcore_is_enabled(lcore_id))
			continue;

		graph_conf.nb_node_patterns = nb_patterns;
		graph_conf.socket_id = rte_lcore_to_socket_id(lcore_id);

		snprintf(dp_layer.graph_name, sizeof(dp_layer.graph_name),
				"worker_%u", lcore_id);

		graph_id = rte_graph_create(dp_layer.graph_name, &graph_conf);
		if (graph_id == RTE_GRAPH_ID_INVALID) {
			DPS_LOG_ERR("Cannot create graph for lcore %u %s", lcore_id, dp_strerror(rte_errno));
			return DP_ERROR;
		}
		if (DP_FAILED(dp_graph_export(dp_layer.graph_name)))
			return DP_ERROR;

		dp_layer.graph_id = graph_id;
		dp_layer.graph = rte_graph_lookup(dp_layer.graph_name);
		if (!dp_layer.graph) {
			DPS_LOG_ERR("Graph %s not found after creation for lcore %u", dp_layer.graph_name, lcore_id);
			return DP_ERROR;
		}
	}

	return DP_OK;
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
