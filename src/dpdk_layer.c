#include <unistd.h>
#include "rte_malloc.h"
#include "dpdk_layer.h"
#include "dp_mbuf_dyn.h"
#include "node_api.h"
#include "dp_lpm.h"
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
#include "rte_flow/dp_rte_flow_init.h"
#include "monitoring/dp_monitoring.h"
#include "dp_port.h"
#include "dp_error.h"
#include "dp_log.h"

static volatile bool force_quit;
static int last_assigned_vf_idx = 0;
static int last_pf1_hairpin_tx_rx_queue_offset = 1;
static pthread_t ctrl_thread_tid;
static struct rte_timer timer;
static uint64_t timer_res;

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

static void signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
		printf("\n\nSignal %d received, preparing to exit...\n",
		       signum);
		force_quit = true;
		pthread_cancel(ctrl_thread_tid);
	}
}

static void timer_cb()
{
	if (dp_conf_is_ipv6_overlay_enabled()) {
		trigger_nd_ra();
		trigger_nd_unsol_adv();
	}
	trigger_garp();
	dp_send_event_timer_msg();
}

// TODO(plague): neds proper retval
int dp_dpdk_init()
{
	uint64_t hz;
	uint8_t lcore_id;

	memset(&dp_layer, 0, sizeof(struct dp_dpdk_layer));

	dp_layer.rte_mempool = rte_pktmbuf_pool_create("mbuf_pool", NB_MBUF(DP_MAX_PORTS),
												   MEMPOOL_CACHE_SIZE, RTE_CACHE_LINE_SIZE + 32,
												   RTE_MBUF_DEFAULT_BUF_SIZE,
												   rte_socket_id());

	if (dp_layer.rte_mempool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot init mbuf pool\n");

	dp_layer.num_of_vfs = dp_get_num_of_vfs();
	if (DP_FAILED(dp_layer.num_of_vfs))
		return DP_ERROR;

	dp_layer.nr_std_rx_queues = DP_NR_STD_RX_QUEUES;
	dp_layer.nr_std_tx_queues = DP_NR_STD_TX_QUEUES;

	dp_layer.nr_vf_hairpin_rx_tx_queues = DP_NR_VF_HAIRPIN_RX_TX_QUEUES;
	dp_layer.nr_pf_hairpin_rx_tx_queues = DP_NR_VF_HAIRPIN_RX_TX_QUEUES * dp_layer.num_of_vfs;

	dp_layer.grpc_tx_queue = rte_ring_create("grpc_tx_queue", DP_INTERNAL_Q_SIZE, rte_socket_id(), RING_F_SC_DEQ | RING_F_SP_ENQ);
	if (!dp_layer.grpc_tx_queue)
		printf("Error creating grpc tx queue\n");
	dp_layer.grpc_rx_queue = rte_ring_create("grpc_rx_queue", DP_INTERNAL_Q_SIZE, rte_socket_id(), RING_F_SC_DEQ | RING_F_SP_ENQ);
	if (!dp_layer.grpc_rx_queue)
		printf("Error creating grpc rx queue\n");
	dp_layer.periodic_msg_queue = rte_ring_create("periodic_msg_queue", DP_INTERNAL_Q_SIZE, rte_socket_id(), RING_F_SC_DEQ | RING_F_SP_ENQ);
	if (!dp_layer.periodic_msg_queue)
		printf("Error creating periodic_msg_queue queue\n");
	/* TODO Monitoring queue needs to be multiproducer, single consumer */
	dp_layer.monitoring_rx_queue = rte_ring_create("monitoring_rx_queue", DP_INTERNAL_Q_SIZE, rte_socket_id(), RING_F_SC_DEQ | RING_F_SP_ENQ);
	if (!dp_layer.monitoring_rx_queue)
		printf("Error creating monitoring rx queue\n");

	// init the timer subsystem
	rte_timer_subsystem_init();
	//init the timer
	rte_timer_init(&timer);


	hz = rte_get_timer_hz();
	timer_res = hz * 10; // 10 seconds
	lcore_id = rte_lcore_id();
	rte_timer_reset(&timer, hz*30, PERIODICAL, lcore_id, timer_cb, NULL);

	force_quit = false;

	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	return DP_OK;
}


static int graph_main_loop()
{
	struct rte_graph *graph = dp_layer.graph;

	dp_log_set_thread_name("worker");

	while (!force_quit)
		rte_graph_walk(graph);

	return 0;
}

static void print_stats(char *msg_out, size_t msg_len)
{
	const char topLeft[] = {27, '[', '1', ';', '1', 'H', '\0'};
	const char clr[] = {27, '[', '2', 'J', '\0'};
	struct rte_graph_cluster_stats_param s_param;
	struct rte_graph_cluster_stats *stats;
	const char *pattern = "worker_*";

	/* Prepare stats object */
	memset(&s_param, 0, sizeof(s_param));
	s_param.f = stdout;
	s_param.socket_id = SOCKET_ID_ANY;
	s_param.graph_patterns = &pattern;
	s_param.nb_graph_patterns = 1;

	stats = rte_graph_cluster_stats_create(&s_param);
	if (stats == NULL)
		rte_exit(EXIT_FAILURE, "Unable to create stats object\n");

	/* Clear screen and move to top left */
	printf("%s%s", clr, topLeft);
	rte_graph_cluster_stats_get(stats, 0);
	print_link_info(0, msg_out, msg_len);
	//if (strlen(msg_out))
	//bb	printf("%s", msg_out);

	sleep(1);

	rte_graph_cluster_stats_destroy(stats);
}

static int main_core_loop(void)
{
	uint64_t prev_tsc = 0, cur_tsc;
	char *msg_out = NULL;
	size_t msg_out_len_max = 400;

	msg_out = malloc(msg_out_len_max + 1);

	while (!force_quit) {
		/* Accumulate and print stats on main until exit */
		if (dp_conf_is_stats_enabled() && rte_graph_has_stats_feature())
			print_stats(msg_out, msg_out_len_max);

		cur_tsc = rte_get_timer_cycles();
		if ((cur_tsc - prev_tsc) > timer_res) {
			rte_timer_manage();
			prev_tsc = cur_tsc;
		}
	}

	free(msg_out);
	return DP_OK;
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

void dp_dpdk_exit(void)
{
	uint32_t i;

	for (i = 0; i < dp_layer.dp_port_cnt; i++)
		free(dp_layer.ports[i]);
}

static int dp_cfg_ethdev(int port_id)
{
	struct rte_node_ethdev_config *ethdev_conf;

	ethdev_conf = &dp_layer.ethdev_conf[dp_layer.dp_port_cnt - 1];
	ethdev_conf->port_id = port_id;
	ethdev_conf->mp_count = 1;
	ethdev_conf->mp = &dp_layer.rte_mempool;
	return 0;
}

// TODO(plague): move to dp_port?
static int dp_port_prepare(dp_port_type type, int port_id,
						   struct dp_port_ext *port_ext)
{
	struct dp_port *dp_port;

	dp_port = dp_port_create(&dp_layer, type);
	if (dp_port) {
		dp_port_init(dp_port, port_id, port_ext);
		dp_layer.ports[dp_layer.dp_port_cnt++] = dp_port;
		dp_cfg_ethdev(port_id);
	}
	return 0;
}

// TODO(plague): move to dp_port?
static int dp_port_flow_isolate(int port_id)
{
	struct rte_flow_error error;
	int set = 1;

	/* Poisoning to make sure PMDs update it in case of error. */
	memset(&error, 0x66, sizeof(error));
	if (rte_flow_isolate(port_id, set, &error))
		DPS_LOG_ERR("Flow can't be validated, message: %s", error.message ? error.message : "(no stated reason)");
	DPS_LOG_INFO("Ingress traffic on port %u is %s to the defined flow rules",
			port_id,
			set ? "now restricted" : "not restricted anymore");
	return 0;
}


void set_vf_port_status_as_attached(int port_id)
{
	dp_set_vf_attach_status(&dp_layer, port_id, DP_VF_PORT_ATTACH);
}

dp_vf_port_attach_status get_vf_port_attach_status(int port_id)
{
	dp_vf_port_attach_status status = get_vf_attach_status(&dp_layer, port_id);
	return status;
}

static int dp_install_isolated_mode(int port_id)
{
	switch (dp_conf_get_overlay_type()) {
	case DP_CONF_OVERLAY_TYPE_IPIP:
		DPS_LOG_INFO("Init isolation flow rule for IPinIP tunnels");
		if (DP_FAILED(dp_install_isolated_mode_ipip(port_id, DP_IP_PROTO_IPv4_ENCAP))
			|| DP_FAILED(dp_install_isolated_mode_ipip(port_id, DP_IP_PROTO_IPv6_ENCAP)))
			return DP_ERROR;
		break;
	case DP_CONF_OVERLAY_TYPE_GENEVE:
		DPS_LOG_INFO("Init isolation flow rule for GENEVE tunnels");
		if (DP_FAILED(dp_install_isolated_mode_geneve(port_id)))
			return DP_ERROR;
		break;
	}
	return DP_OK;
}

static void allocate_pf_hairpin_tx_queue(uint16_t port_id, uint16_t peer_pf_port_id, uint16_t hairpin_queue_offset)
{

	struct dp_port *vf_port;

	vf_port = dp_get_vf_port_per_id(&dp_layer, port_id);

	vf_port->peer_pf_port_id = peer_pf_port_id;
	vf_port->peer_pf_hairpin_tx_rx_queue_offset = hairpin_queue_offset;
}

uint16_t get_pf_hairpin_rx_queue(uint16_t port_id)
{
	uint16_t pf_rx_q_index = 0;

	for (uint8_t i = 0; i < dp_layer.dp_port_cnt; i++) {
		if (dp_layer.ports[i]->dp_p_type == DP_PORT_VF && dp_layer.ports[i]->dp_port_id == port_id) {
			pf_rx_q_index =  dp_layer.nr_std_rx_queues - 1 + dp_layer.ports[i]->peer_pf_hairpin_tx_rx_queue_offset;
			break;
		}
	}

	return pf_rx_q_index;
}

int dp_init_interface(struct dp_port_ext *port, dp_port_type type)
{
	uint32_t ret, cnt = 0;
	uint16_t nr_ports, port_id;
	struct dp_port_ext dp_port_ext;
	char ifname[IF_NAMESIZE] = {0};

	nr_ports = rte_eth_dev_count_avail();
	if (nr_ports == 0)
		rte_exit(EXIT_FAILURE, "no Ethernet ports found\n");

	dp_port_ext = *port;

	RTE_ETH_FOREACH_DEV(port_id) {
		struct rte_eth_dev_info dev_info;

		ret = dp_get_dev_info(port_id, &dev_info, ifname);
		if (ret != 0)
			rte_exit(EXIT_FAILURE,
					"Error during getting device (port %u) info: %s\n",
					port_id, strerror(-ret));

		if ((type == DP_PORT_PF) && (strncmp(dp_port_ext.port_name, ifname, IF_NAMESIZE) == 0)) {

			if (dp_conf_get_nic_type() != DP_CONF_NIC_TYPE_TAP)
				dp_port_flow_isolate(port_id);

			dp_port_prepare(type, port_id, &dp_port_ext);
			dp_add_pf_port_id(port_id);

			// Only PF's status is handled for now since it is critical for cross-hypervisor communication
			rte_eth_dev_callback_register(port_id, RTE_ETH_EVENT_INTR_LSC, dp_link_status_change_event_callback, NULL);
			return port_id;
		}

		if ((type == DP_PORT_VF) &&
			(strstr(ifname, dp_port_ext.port_name) != NULL)) {
			if (cnt == last_assigned_vf_idx) {
				dp_port_prepare(type, port_id, &dp_port_ext);
				last_assigned_vf_idx++;

				//if it belongs to pf0, assign a tx queue from pf1 for it
				if (dp_conf_is_offload_enabled()) {
					allocate_pf_hairpin_tx_queue(port_id, dp_get_pf1_port_id(), last_pf1_hairpin_tx_rx_queue_offset);
					last_pf1_hairpin_tx_rx_queue_offset++;
				}
				return port_id;
			}
			cnt++;
		}
	}

	return -1;
}

static int setup_hairpin_rx_tx_queues(uint16_t port_id, uint16_t peer_port_id, uint8_t port_hairpin_rx_q_offset, uint8_t peer_port_hairpin_tx_q_offset)
{

	uint32_t hairpin_queue, peer_hairpin_queue = 0;
	int ret = 0;
	struct rte_eth_hairpin_conf hairpin_conf = {
		.peer_count = 1,
		.manual_bind = 1,
		.tx_explicit = 1,
	};

	struct rte_eth_rxq_info rxq_info = { 0 };
	struct rte_eth_txq_info txq_info = { 0 };

	hairpin_conf.peers[0].port = peer_port_id;
	peer_hairpin_queue =  dp_layer.nr_std_tx_queues - 1 + peer_port_hairpin_tx_q_offset;
	hairpin_conf.peers[0].queue = peer_hairpin_queue;
	rte_eth_rx_queue_info_get(port_id, 0, &rxq_info);

	hairpin_queue =  dp_layer.nr_std_rx_queues - 1 + port_hairpin_rx_q_offset;
	printf("setup from port %d to port %d, rxq %d to txq %d\n", port_id, peer_port_id, hairpin_queue, peer_hairpin_queue);
	ret = rte_eth_rx_hairpin_queue_setup(
				port_id, hairpin_queue,
				rxq_info.nb_desc, &hairpin_conf);

	if (ret != 0) {
		printf("Error: configure hairpin rx->tx queue from %d to %d\n ", port_id, peer_port_id);
		return -1;
	}

	hairpin_conf.peers[0].port = port_id;
	hairpin_conf.peers[0].queue = hairpin_queue;
	rte_eth_tx_queue_info_get(peer_port_id, 0, &txq_info);
	printf("setup from port %d to port %d, txq %d to rxq %d\n", peer_port_id, port_id, peer_hairpin_queue, hairpin_queue);
	ret = rte_eth_tx_hairpin_queue_setup(
				peer_port_id, peer_hairpin_queue,
				txq_info.nb_desc, &hairpin_conf);
	if (ret != 0) {
		printf("Error: configure hairpin tx->rx queue from %d to %d\n ", peer_port_id, port_id);
		return -1;
	}
	return ret;
}

int hairpin_vfs_to_pf(void)
{

	int ret = 0;

	for (uint8_t i = 0; i < dp_layer.dp_port_cnt; i++) {
		if (dp_layer.ports[i]->dp_p_type == DP_PORT_VF) {
			ret = setup_hairpin_rx_tx_queues(dp_layer.ports[i]->dp_port_id, dp_layer.ports[i]->peer_pf_port_id,
											1, dp_layer.ports[i]->peer_pf_hairpin_tx_rx_queue_offset);
			if (ret < 0) {
				printf("Failed to setup hairpin rx queue for vf %d\n", dp_layer.ports[i]->dp_port_id);
				return ret;
			}

			ret = setup_hairpin_rx_tx_queues(dp_layer.ports[i]->peer_pf_port_id, dp_layer.ports[i]->dp_port_id,
											dp_layer.ports[i]->peer_pf_hairpin_tx_rx_queue_offset, 1);
			if (ret < 0) {
				printf("Failed to setup hairpin tx queue for vf %d\n", dp_layer.ports[i]->dp_port_id);
				return ret;
			}
		}
	}

	return ret;
}

int hairpin_ports_bind(uint16_t tx_port_id, uint16_t rx_port_id)
{
	int ret = 0;

	ret = rte_eth_hairpin_bind(tx_port_id, rx_port_id);
	if (ret < 0) {
		printf("Failed to bind %d to %d, due to error: %d\n", tx_port_id, rx_port_id, ret);
		return ret;
	}
	return ret;
}

int bind_vf_with_peer_pf_port(uint16_t port_id)
{
	int ret = 0;
	uint16_t peer_pf_port;

	for (uint8_t i = 0; i < dp_layer.dp_port_cnt; i++) {
		if (dp_layer.ports[i]->dp_p_type == DP_PORT_VF && dp_layer.ports[i]->dp_port_id == port_id) {
			peer_pf_port = dp_layer.ports[i]->peer_pf_port_id;
			// bind txq of peer_pf_port to rxq of port_id
			printf("Try to bind %d to %d\n", peer_pf_port, port_id);
			ret = rte_eth_hairpin_bind(peer_pf_port, port_id);
			if (ret < 0) {
				printf("Failed to bind %d to %d, due to error: %d\n", peer_pf_port, port_id, ret);
				return ret;
			}
			printf("Try to bind %d to %d\n", port_id, peer_pf_port);
			ret = rte_eth_hairpin_bind(port_id, peer_pf_port);
			if (ret < 0) {
				printf("Failed to bind %d to %d, due to error: %d\n", port_id, peer_pf_port, ret);
				return ret;
			}
			break;
		}
	}

	return ret;
}

int hairpin_ports_bind_all(uint16_t port_id)
{
	int ret = 0;
	int i = 0;
	uint16_t peer_ports[RTE_MAX_ETHPORTS];
	int peer_ports_num = 0;

	peer_ports_num = rte_eth_hairpin_get_peer_ports(port_id,
			peer_ports, RTE_MAX_ETHPORTS, 1);

	if (peer_ports_num < 0)
		return -1;

	for (i = 0; i < peer_ports_num; i++) {
		ret = hairpin_ports_bind(port_id, peer_ports[i]);
		if (ret < 0)
			return ret;
	}

	return ret;
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
	struct ethdev_tx_node_main *tx_node_data;
	char name[RTE_NODE_NAMESIZE];
	const char *next_nodes = name;
	struct rx_node_config rx_cfg;
	struct rx_periodic_node_config rx_periodic_cfg;
	int ret, i, id;
	struct rte_graph_param graph_conf = {0};
	const char **node_patterns;
	int nb_patterns;
	uint32_t lcore_id;

	/* Graph Initialization */
	nb_patterns = RTE_DIM(default_patterns);
	// TODO(plague): this constant should be DP_NR_STD_RX_QUEUES, but needs testing as it is smaller (1)!
	node_patterns = malloc((2 + nb_patterns) * sizeof(*node_patterns));
	// TODO(plague): thre's no free(), dp_graph_free() needed
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

	/* it is not really needed to init queues in this way, and init can be done within node's init function */
	rx_periodic_cfg.periodic_msg_queue = dp_layer.periodic_msg_queue;
	rx_periodic_cfg.grpc_tx = dp_layer.grpc_tx_queue;
	rx_periodic_cfg.grpc_rx = dp_layer.grpc_rx_queue;
	rx_periodic_cfg.monitoring_rx = dp_layer.monitoring_rx_queue;
	// TODO(plague): the whole DP node api needs work, either this will be void or properly check
	// (this will apply on many places below)
	ret = config_rx_periodic_node(&rx_periodic_cfg);

	for (i = 0; i < dp_layer.dp_port_cnt; i++) {
		// TODO(plague): just create a function for the loop?
		snprintf(name, sizeof(name), "%u-%u", dp_layer.ports[i]->dp_port_id, 0);
		/* Clone a new rx node with same edges as parent */
		id = rte_node_clone(rx_node->id, name);
		if (id == RTE_NODE_ID_INVALID) {
			DPS_LOG_ERR("Cannot clone rx node %s", dp_strerror(rte_errno));
			return DP_ERROR;
		}
		rx_cfg.port_id = dp_layer.ports[i]->dp_port_id;
		rx_cfg.queue_id = 0;
		rx_cfg.node_id = id;
		// TODO(plague): DP node api
		ret = config_rx_node(&rx_cfg);

		snprintf(name, sizeof(name), "%u", dp_layer.ports[i]->dp_port_id);
		id = rte_node_clone(tx_node->id, name);
		if (id == RTE_NODE_ID_INVALID) {
			DPS_LOG_ERR("Cannot clone rx node %s", dp_strerror(rte_errno));
			return DP_ERROR;
		}
		tx_node_data->nodes[dp_layer.ports[i]->dp_port_id] = id;
		tx_node_data->port_ids[dp_layer.ports[i]->dp_port_id] = dp_layer.ports[i]->dp_port_id;

		snprintf(name, sizeof(name), "tx-%u", dp_layer.ports[i]->dp_port_id);
		if (dp_layer.ports[i]->dp_p_type == DP_PORT_VF) {
			// TODO(plague): all these can fail with RTE_EDGE_ID_INVALID and set rte_errno
			rte_node_edge_update(arp_node->id, RTE_EDGE_ID_INVALID, &next_nodes, 1);
			// TODO(plague): maybe rework DP node api to do each in one call
			// TODO(plague): update retval checks
			ret = arp_set_next(dp_layer.ports[i]->dp_port_id, rte_node_edge_count(arp_node->id) - 1);
			if (ret < 0) {
				DPS_LOG_ERR("Node set next failed %s", dp_strerror(ret));
				return ret;
			}
			rte_node_edge_update(rx_periodic_node->id, RTE_EDGE_ID_INVALID, &next_nodes, 1);
			ret = rx_periodic_set_next(dp_layer.ports[i]->dp_port_id, rte_node_edge_count(rx_periodic_node->id) - 1);
			if (ret < 0) {
				DPS_LOG_ERR("Node set next failed %s", dp_strerror(ret));
				return ret;
			}
			rte_node_edge_update(ipv6_nd_node->id, RTE_EDGE_ID_INVALID, &next_nodes, 1);
			ret = ipv6_nd_set_next(dp_layer.ports[i]->dp_port_id, rte_node_edge_count(ipv6_nd_node->id) - 1);
			if (ret < 0) {
				DPS_LOG_ERR("Node set next failed %s", dp_strerror(ret));
				return ret;
			}
			rte_node_edge_update(dhcp_node->id, RTE_EDGE_ID_INVALID, &next_nodes, 1);
			ret = dhcp_set_next(dp_layer.ports[i]->dp_port_id, rte_node_edge_count(dhcp_node->id) - 1);
			if (ret < 0) {
				DPS_LOG_ERR("Node set next failed %s", dp_strerror(ret));
				return ret;
			}
			rte_node_edge_update(dhcpv6_node->id, RTE_EDGE_ID_INVALID, &next_nodes, 1);
			ret = dhcpv6_set_next(dp_layer.ports[i]->dp_port_id, rte_node_edge_count(dhcpv6_node->id) - 1);
			if (ret < 0) {
				DPS_LOG_ERR("Node set next failed %s", dp_strerror(ret));
				return ret;
			}
			rte_node_edge_update(l2_decap_node->id, RTE_EDGE_ID_INVALID, &next_nodes, 1);
			ret = l2_decap_set_next(dp_layer.ports[i]->dp_port_id, rte_node_edge_count(l2_decap_node->id) - 1);
			if (ret < 0) {
				DPS_LOG_ERR("Node set next failed %s", dp_strerror(ret));
				return ret;
			}
		}

		if (dp_layer.ports[i]->dp_p_type == DP_PORT_PF) {
			rte_node_edge_update(ipv6_encap_node->id, RTE_EDGE_ID_INVALID, &next_nodes, 1);
			ret = ipv6_encap_set_next(dp_layer.ports[i]->dp_port_id, rte_node_edge_count(ipv6_encap_node->id) - 1);
			if (ret < 0) {
				DPS_LOG_ERR("Node set next failed %s", dp_strerror(ret));
				return ret;
			}
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

int dp_start_interface(struct dp_port_ext *port_ext, int portid, dp_port_type type)
{
	// TODO(plague): refactor to return the port (prevents multiple lookups)
	if (DP_FAILED(dp_port_allocate(&dp_layer, portid, port_ext, type)))
		return DP_ERROR;

	if (type == DP_PORT_PF && dp_conf_get_nic_type() != DP_CONF_NIC_TYPE_TAP)
		if (DP_FAILED(dp_install_isolated_mode(portid)))
			return DP_ERROR;

	enable_rx_node(portid);
	// TODO(plague): currently silently fails on bad id,
	// but once this has pointer, it can be nicer
	dp_port_set_link_status(&dp_layer, portid, RTE_ETH_LINK_UP);
	return DP_OK;
}

void dp_stop_interface(int portid, dp_port_type type)
{
	int ret = 0;

	disable_rx_node(portid);

	/* Tap interfaces in test environment can not be stopped */
	/* due to a bug in dpdk tap device library. */
	if (dp_conf_get_nic_type() != DP_CONF_NIC_TYPE_TAP)
		ret = rte_eth_dev_stop(portid);

	if (ret < 0) {
		rte_exit(EXIT_FAILURE,
				"rte_eth_dev_stop:err=%d, port=%u\n",
				ret, portid);
	}
	if (!dp_port_deallocate(&dp_layer, portid))
		printf("Port deallocation failed for port %d\n", portid);
}

// TODO dp_get_dpdk_layer() ?
struct dp_dpdk_layer *get_dpdk_layer()
{
	return &dp_layer;
}

pthread_t *dp_get_ctrl_thread_id()
{
	return &ctrl_thread_tid;
}
