#include "dpdk_layer.h"
#include "dp_mbuf_dyn.h"
#include "node_api.h"
#include "dp_lpm.h"
#include "dp_util.h"
#include "nodes/tx_node_priv.h"
#include "nodes/rx_node_priv.h"
#include "nodes/arp_node_priv.h"
#include "nodes/ipv6_nd_node.h"
#include "nodes/dhcp_node.h"
#include "nodes/l2_decap_node.h"
#include "nodes/ipv6_encap_node.h"
#include "nodes/geneve_encap_node.h"

static volatile bool force_quit;

static const char * const default_patterns[] = {
	"rx-*",
	"cls",
	"arp",
	"ipv6_nd",
	"ipv4_lookup",
	"ipv6_lookup",
	"dhcp",
	"l2_decap",
	"ipv6_encap",
	"ipv6_decap",
	"geneve_encap",
	"geneve_decap",
	"tx-*",
	"drop",
};

static struct dp_dpdk_layer dp_layer;
/*TODO these shouldnt be hardcoded */
static struct underlay_conf gen_conf = {
	.dst_port = 6081,
	.src_port = 6081,
	.rsvd1 = 0,
	.vni[0] = 0xde,
	.vni[1] = 0xde,
	.vni[2] = 0xde,
	.trgt_ip6[0] = 0x2a,
	.trgt_ip6[1] = 0x10,
	.trgt_ip6[2] = 0xaf,
	.trgt_ip6[3] = 0xc0,
	.trgt_ip6[4] = 0xe0,
	.trgt_ip6[5] = 0x1f,
	.trgt_ip6[6] = 0x00,
	.trgt_ip6[7] = 0xf4,
	.trgt_ip6[15] = 0x03,
	.src_ip6[0] = 0x2a,
	.src_ip6[1] = 0x10,
	.src_ip6[2] = 0xaf,
	.src_ip6[3] = 0xc0,
	.src_ip6[4] = 0xe0,
	.src_ip6[5] = 0x1f,
	.src_ip6[6] = 0x00,
	.src_ip6[7] = 0xf4,
	.src_ip6[15] = 0x02,
};

static void signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
		printf("\n\nSignal %d received, preparing to exit...\n",
		       signum);
		force_quit = true;

	}
}

int dp_dpdk_init(int argc, char **argv)
{
	int ret;

	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_panic("Cannot init EAL\n");
	
	memset(&dp_layer, 0, sizeof(struct dp_dpdk_layer));

	dp_layer.rte_mempool = rte_pktmbuf_pool_create("mbuf_pool", NB_MBUF(DP_MAX_PORTS), 
												   MEMPOOL_CACHE_SIZE, RTE_CACHE_LINE_SIZE,
												   RTE_MBUF_DEFAULT_BUF_SIZE,
												   rte_socket_id());
	if (dp_layer.rte_mempool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot init mbuf pool\n");

	dp_layer.nr_rx_queues = DP_NR_RX_QUEUES;
	dp_layer.nr_tx_queues = DP_NR_TX_QUEUES;

	if (rte_mbuf_dyn_flow_register() < 0)
		printf("Error registering private mbuf field\n");

	setup_lpm(rte_socket_id());
	force_quit = false;

	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	return ret;
}

static int graph_main_loop()
{	
	struct rte_graph *graph;

	while (!force_quit) {
			graph = dp_layer.graph;
			rte_graph_walk(graph);
	}
	return 0;
}

static void print_stats(void)
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

	while (!force_quit) {
		/* Clear screen and move to top left */
		printf("%s%s", clr, topLeft);
		rte_graph_cluster_stats_get(stats, 0);
		rte_delay_ms(1E3);
	}

	rte_graph_cluster_stats_destroy(stats);
}

int dp_dpdk_main_loop()
{
	printf("DPDK main loop started\n ");	

	/* Launch per-lcore init on every worker lcore */
	rte_eal_mp_remote_launch(graph_main_loop, NULL, SKIP_MAIN);

	/* Accumulate and print stats on main until exit */
	if (dp_is_stats_enabled() && rte_graph_has_stats_feature())
		print_stats();

	return 0;
}

void dp_dpdk_exit()
{
	uint32_t i;

	for (i = 0; i < dp_layer.dp_port_cnt; i++)
		free(dp_layer.ports[i]); 

	rte_eal_cleanup();
}

static int dp_cfg_ethdev(int port_id)
{
	struct rte_node_ethdev_config *ethdev_conf;

	ethdev_conf = &dp_layer.ethdev_conf[dp_layer.dp_port_cnt - 1];
	ethdev_conf->num_rx_queues = dp_layer.nr_rx_queues;
	ethdev_conf->num_tx_queues = dp_layer.nr_tx_queues;
	ethdev_conf->port_id = port_id;
	ethdev_conf->mp_count = 1;
	ethdev_conf->mp = &dp_layer.rte_mempool;
	return 0;
}

static int dp_port_prepare(dp_port_type type, int p_port_id, int port_id, 
						   struct dp_port_ext *port_ext)
{
	struct dp_port *dp_port;

	dp_port = dp_port_create(&dp_layer, type);
	if (dp_port){
		dp_port_init(dp_port, p_port_id, port_id, port_ext);
		dp_layer.ports[dp_layer.dp_port_cnt++] = dp_port;
		dp_cfg_ethdev(port_id);
	}
	return 0;	
}


static int dp_port_flow_isolate(int port_id)
{
	struct rte_flow_error error;
	int set = 1;

	/* Poisoning to make sure PMDs update it in case of error. */
	memset(&error, 0x66, sizeof(error));
	if (rte_flow_isolate(port_id, set, &error))
		printf("Flow can't be validated message: %s\n", error.message ? error.message : "(no stated reason)");
	printf("Ingress traffic on port %u is %s to the defined flow rules\n",
			port_id,
			set ? "now restricted" : "not restricted anymore");
	return 0;
}

static void dp_install_isolated_mode(int port_id)
{
	struct rte_flow_item_eth eth_spec;
	struct rte_flow_item_eth eth_mask;
	struct rte_flow_item_ipv6 ipv6_spec;
	struct rte_flow_item_ipv6 ipv6_mask;
	struct rte_flow_item_udp udp_spec;
	struct rte_flow_item_udp udp_mask;
	struct rte_flow_attr attr;
	struct rte_flow_item pattern[4];
	struct rte_flow_action action[2];
	struct underlay_conf *u_conf;
	struct rte_flow_action_queue q;
	uint8_t	dst_addr[16] = "\xff\xff\xff\xff\xff\xff\xff\xff"
						   "\xff\xff\xff\xff\xff\xff\xff\xff";
	int pattern_cnt = 0, res;
	struct rte_flow *flow;

	u_conf = get_underlay_conf();

	attr.ingress = 1;
	attr.priority = 0;
	attr.transfer = 0;
	memset(pattern, 0, sizeof(pattern));
	memset(action, 0, sizeof(action));
	memset(&eth_spec, 0, sizeof(struct rte_flow_item_eth));
	memset(&eth_mask, 0, sizeof(struct rte_flow_item_eth));
	eth_spec.type = htons(RTE_ETHER_TYPE_IPV6);
	eth_mask.type = htons(0xffff);
	pattern[pattern_cnt].type = RTE_FLOW_ITEM_TYPE_ETH;
	pattern[pattern_cnt].spec = &eth_spec;
	pattern[pattern_cnt].mask = &eth_mask;
	pattern_cnt++;

	memset(&ipv6_spec, 0, sizeof(struct rte_flow_item_ipv6));
	memset(&ipv6_mask, 0, sizeof(struct rte_flow_item_ipv6));
	ipv6_spec.hdr.proto = DP_IP_PROTO_UDP;
	rte_memcpy(ipv6_spec.hdr.dst_addr, u_conf->src_ip6, sizeof(ipv6_spec.hdr.dst_addr));
	ipv6_mask.hdr.proto = 0xff;
	rte_memcpy(ipv6_mask.hdr.dst_addr, dst_addr, sizeof(ipv6_spec.hdr.dst_addr));
	pattern[pattern_cnt].type = RTE_FLOW_ITEM_TYPE_IPV6;
	pattern[pattern_cnt].spec = &ipv6_spec;
	pattern[pattern_cnt].mask = &ipv6_mask;
	pattern_cnt++;

	memset(&udp_spec, 0, sizeof(struct rte_flow_item_udp));
	memset(&udp_mask, 0, sizeof(struct rte_flow_item_udp));
	udp_spec.hdr.dst_port = htons(u_conf->src_port);
	udp_spec.hdr.src_port = htons(u_conf->dst_port);
	udp_mask.hdr.dst_port = 0xffff;
	udp_mask.hdr.src_port = 0xffff;
	pattern[pattern_cnt].type = RTE_FLOW_ITEM_TYPE_UDP;
	pattern[pattern_cnt].spec = &udp_spec;
	pattern[pattern_cnt].mask = &udp_mask;
	pattern_cnt++;

	pattern[pattern_cnt].type = RTE_FLOW_ITEM_TYPE_END;
	pattern_cnt++;

	action[0].type = RTE_FLOW_ACTION_TYPE_QUEUE;
	q.index = 0;
	action[0].conf = &q; 
	action[1].type = RTE_FLOW_ACTION_TYPE_END;

	struct rte_flow_error error;
	res = rte_flow_validate(port_id, &attr, pattern, action, &error);

	if (res) { 
		printf("Isolete flow can't be validated message: %s\n", error.message ? error.message : "(no stated reason)");
	} else {
		printf("Isolate flow validated on port %d \n ", port_id);
		flow = rte_flow_create(port_id, &attr, pattern, action, &error);
		if (!flow)
			printf("Isolate flow can't be created message: %s\n", error.message ? error.message : "(no stated reason)");
	}
}

static void dp_get_vf_name_from_pf_name(char *vf_name /* out */, char *pf_name /* in */)
{
	int pf_len = strnlen(pf_name, IFNAMSIZ);
	char temp[IFNAMSIZ];
	
	memcpy(temp, pf_name, IFNAMSIZ);
	if (pf_len > 3 && (temp[pf_len - 3] == 'n') && (temp[pf_len - 2] == 'p'))
		temp[pf_len - 3] = '\0';
	
	snprintf(vf_name, IFNAMSIZ + 1, "%s_", temp);
}

static int dp_initialize_vfs(struct dp_port_ext *ports, int port_count)
{
	uint32_t ret, cnt, pf_port_id = 0;
	uint16_t nr_ports;
	struct dp_port_ext dp_port_ext;
	char ifname[IF_NAMESIZE] = {0};
	char ifname_v[IF_NAMESIZE + 1] = {0};
	static int done = 0; 

	nr_ports = rte_eth_dev_count_avail();
	if (nr_ports == 0)
		rte_exit(EXIT_FAILURE, ":: no Ethernet ports found\n");

	for (cnt = 0; cnt < port_count; cnt++) {
		uint16_t port_id;

		dp_port_ext = *ports;
		printf("Looking for VFs of PF %s \n", dp_port_ext.port_name);

		RTE_ETH_FOREACH_DEV(port_id) {
			struct rte_eth_dev_info dev_info;

			ret = rte_eth_dev_info_get(port_id, &dev_info);
			if (ret != 0)
				rte_exit(EXIT_FAILURE,
						"Error during getting device (port %u) info: %s\n",
						port_id, strerror(-ret));

			if_indextoname(dev_info.if_index, ifname);
			if (strncmp(dp_port_ext.port_name, ifname, IF_NAMESIZE) == 0) {
				pf_port_id = port_id;
				dp_port_flow_isolate(port_id);
				dp_port_prepare(DP_PORT_PF, pf_port_id, port_id, &dp_port_ext);
				dp_install_isolated_mode(port_id);
			}

			dp_get_vf_name_from_pf_name(ifname_v, dp_port_ext.port_name);
			if ((strstr(ifname, ifname_v) != NULL) && (done < 2)) { 
				dp_port_prepare(DP_PORT_VF, pf_port_id, port_id, &dp_port_ext);
				done++;
			}	
		}
	}
	return 0;
}

static int dp_init_graph()
{
	struct rte_node_register *rx_node, *tx_node, *arp_node, *ipv6_encap_node;
	struct rte_node_register *dhcp_node, *l2_decap_node, *ipv6_nd_node;
	struct ethdev_tx_node_main *tx_node_data;
	char name[RTE_NODE_NAMESIZE];
	const char *next_nodes = name;
	struct rx_node_config rx_cfg;
	int ret, i, id;
	struct rte_graph_param graph_conf;
	const char **node_patterns;
	int nb_patterns;
	uint32_t lcore_id;

	/* Graph Initialization */
	nb_patterns = RTE_DIM(default_patterns);
	node_patterns = malloc((2 + nb_patterns) * sizeof(*node_patterns));
	if (!node_patterns)
		return -ENOMEM;
	memcpy(node_patterns, default_patterns,
	       nb_patterns * sizeof(*node_patterns));

	memset(&graph_conf, 0, sizeof(graph_conf));
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
	for (i = 0; i < dp_layer.dp_port_cnt; i++) {
		snprintf(name, sizeof(name), "%u-%u", i, 0);
		/* Clone a new rx node with same edges as parent */
		id = rte_node_clone(rx_node->id, name);
		if (id == RTE_NODE_ID_INVALID)
			return -EIO;
		rx_cfg.port_id = dp_layer.ports[i]->dp_port_id;
		rx_cfg.queue_id = 0;
		rx_cfg.node_id = id;
		ret = config_rx_node(&rx_cfg);

		snprintf(name, sizeof(name), "%u", i);
		id = rte_node_clone(tx_node->id, name);
		tx_node_data->nodes[i] = id;

		snprintf(name, sizeof(name), "tx-%u", i);
		if (dp_layer.ports[i]->dp_p_type == DP_PORT_VF) {
			rte_node_edge_update(arp_node->id, RTE_EDGE_ID_INVALID,
						&next_nodes, 1);
			ret = arp_set_next(
				i, rte_node_edge_count(arp_node->id) - 1);
			if (ret < 0)
				return ret;
			rte_node_edge_update(ipv6_nd_node->id, RTE_EDGE_ID_INVALID,
						&next_nodes, 1);
			ret = ipv6_nd_set_next(
				i, rte_node_edge_count(ipv6_nd_node->id) - 1);
			if (ret < 0)
				return ret;
			rte_node_edge_update(dhcp_node->id, RTE_EDGE_ID_INVALID,
			&next_nodes, 1);
			ret = dhcp_set_next(
				i, rte_node_edge_count(dhcp_node->id) - 1);
			if (ret < 0)
				return ret;
			rte_node_edge_update(l2_decap_node->id, RTE_EDGE_ID_INVALID,
			&next_nodes, 1);
			ret = l2_decap_set_next(
				i, rte_node_edge_count(l2_decap_node->id) - 1);
			if (ret < 0)
				return ret;
		}

		if (dp_layer.ports[i]->dp_p_type == DP_PORT_PF) {
			rte_node_edge_update(ipv6_encap_node->id, RTE_EDGE_ID_INVALID,
			&next_nodes, 1);
			ret = ipv6_encap_set_next(
				i, rte_node_edge_count(ipv6_encap_node->id) - 1);
			if (ret < 0)
				return ret;
		}
	}	
	for (lcore_id = 1; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		FILE *f;
		rte_graph_t graph_id;
		int ret;
		char fname[RTE_GRAPH_NAMESIZE + 4];

		if (rte_lcore_is_enabled(lcore_id) == 0)
			continue;
		
		graph_conf.nb_node_patterns = nb_patterns;
		graph_conf.socket_id = rte_lcore_to_socket_id(lcore_id);

		snprintf(dp_layer.graph_name, sizeof(dp_layer.graph_name),
				"worker_%u", lcore_id);

		graph_id = rte_graph_create(dp_layer.graph_name, &graph_conf);
		if (graph_id == RTE_GRAPH_ID_INVALID)
			rte_exit(EXIT_FAILURE,
					"rte_graph_create(): graph_id invalid"
					" for lcore %u\n", lcore_id);
		sprintf(fname, "%s.dot", dp_layer.graph_name);
		f = fopen(fname, "w");
		ret = rte_graph_export(dp_layer.graph_name, f);
		if (ret != 0)
			return -1;
		fclose(f);

		dp_layer.graph_id = graph_id;
		dp_layer.graph = rte_graph_lookup(dp_layer.graph_name);
		/* >8 End of graph initialization. */
		if (!dp_layer.graph)
			rte_exit(EXIT_FAILURE,
					"rte_graph_lookup(): graph %s not found\n",
					dp_layer.graph_name);
	}

	return 0;
} 

int dp_prepare(struct dp_port_ext *ports, int port_count)
{
	int ret;
	/* TODO setunderlay and configure uplink will be done. Parameter should be struct config */

	ret = dp_initialize_vfs(ports, port_count);
	return ret;
}

int dp_allocate_vf(int port_id)
{
	struct dp_port *dp_port;
	int ret = 0;

	dp_port = get_dp_vf_port_with_id(port_id, &dp_layer);

	if (dp_port){ 
		dp_port_allocate(dp_port);
		ret = dp_port->dp_port_id;
	}	

	return ret;
}

int dp_configure_vf(int port_id)
{
	dp_init_graph();
	return 0;
}

 __rte_always_inline struct underlay_conf *get_underlay_conf() {
	return &gen_conf;
}
