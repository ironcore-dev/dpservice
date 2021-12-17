#include <unistd.h>
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
#include "nodes/dhcpv6_node.h"
#include "nodes/l2_decap_node.h"
#include "nodes/ipv6_encap_node.h"
#include "nodes/geneve_encap_node.h"
#include "nodes/rx_periodic_node.h"

static volatile bool force_quit;
static int last_assigned_vf_idx = 0;
static pthread_t ctrl_thread_tid;
static struct rte_timer timer;
static uint64_t timer_res;
static struct rte_mbuf *pkt_buf;

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
	.vni = {0},
	.trgt_ip6 = {0},
	.src_ip6 = {0},
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

static void timer_cb () {
	struct rte_ether_hdr *eth_hdr;
	struct rte_ipv6_hdr *ipv6_hdr;
	struct rs_msg *rs_msg;
	struct icmp6hdr *icmp6_hdr;
	uint16_t pkt_size;

	pkt_buf = rte_pktmbuf_alloc(dp_layer.rte_mempool);
	if(pkt_buf == NULL) {
		printf("rte_mbuf allocation failed\n");
	}
	
	eth_hdr = rte_pktmbuf_mtod(pkt_buf, struct rte_ether_hdr *);
	ipv6_hdr = (struct rte_ipv6_hdr*)(eth_hdr+1);
	rs_msg = (struct rs_msg*) (ipv6_hdr + 1);

	memset(&eth_hdr->s_addr, 0xFF, RTE_ETHER_ADDR_LEN);
    	memset(&eth_hdr->d_addr, 0xFF, RTE_ETHER_ADDR_LEN);
	eth_hdr->ether_type = htons(RTE_ETHER_TYPE_IPV6);

	ipv6_hdr->proto = 0x3a; //ICMP6
	ipv6_hdr->vtc_flow = htonl(0x60000000);
	ipv6_hdr->hop_limits = 255;
	memset(ipv6_hdr->src_addr,0xff,16);
	memset(ipv6_hdr->dst_addr,0xff,16);
	ipv6_hdr->payload_len = htons(sizeof(struct icmp6hdr));

	
	icmp6_hdr = &(rs_msg->icmph);
	memset(icmp6_hdr,0,sizeof(struct icmp6hdr));
	icmp6_hdr->icmp6_type = 133;
	pkt_size = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv6_hdr) + sizeof(struct ra_msg);
	pkt_buf->data_len = pkt_size;
    pkt_buf->pkt_len = pkt_size;

	// send pkt to all allocated VFs
	for (int i = 0; i < dp_layer.dp_port_cnt; i++) {
		if ((dp_layer.ports[i]->dp_p_type == DP_PORT_VF) &&
			dp_layer.ports[i]->dp_allocated) {
			struct rte_mbuf *clone_buf = rte_pktmbuf_copy(pkt_buf,dp_layer.rte_mempool,0,UINT32_MAX);
			clone_buf->port = dp_layer.ports[i]->dp_port_id;
			rte_ring_sp_enqueue(dp_layer.periodic_msg_queue, clone_buf);

			}
	}
	

}

int dp_dpdk_init(int argc, char **argv)
{
	int ret;
	uint64_t hz;
	uint8_t lcore_id;

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
	dp_layer.grpc_queue = rte_ring_create("grpc_queue", 256, rte_socket_id(), 0);
	if (!dp_layer.grpc_queue)
		printf("Error creating grpc queue\n");
	dp_layer.periodic_msg_queue = rte_ring_create("periodic_msg_queue", 256, rte_socket_id(), 0);
	if (!dp_layer.periodic_msg_queue)
		printf("Error creating periodic_msg_queue queue\n");

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

	/* Clear screen and move to top left */
	printf("%s%s", clr, topLeft);
	rte_graph_cluster_stats_get(stats, 0);
	sleep(1);

	rte_graph_cluster_stats_destroy(stats);
}

static int main_core_loop() {
	uint64_t prev_tsc=0, cur_tsc;
	while (!force_quit) {
		/* Accumulate and print stats on main until exit */
		if (dp_is_stats_enabled() && rte_graph_has_stats_feature()) {
			print_stats();
	}
		cur_tsc = rte_get_timer_cycles();
		if((cur_tsc - prev_tsc) > timer_res) {
			rte_timer_manage();
			prev_tsc = cur_tsc;
		}
	}
	
	return 0;
}

int dp_dpdk_main_loop()
{/*
	struct dp_port_ext pf_port;
	int port_id, vni = 100, t_vni = 100, machine_id = 50;
	int ip_addr = RTE_IPV4(172, 34, 0, 1);
	uint8_t trgt_ip6[16];*/
	

	printf("DPDK main loop started\n ");

/*	port_id = dp_get_next_avail_vf_id(&dp_layer, DP_PORT_VF);
	setup_lpm(port_id, machine_id, vni, rte_eth_dev_socket_id(port_id));
	dp_set_dhcp_range_ip4(port_id, ip_addr, 32, rte_eth_dev_socket_id(port_id));
	dp_add_route(port_id, vni, 0, ip_addr, NULL, 32, rte_eth_dev_socket_id(port_id));
	dp_start_interface(&pf_port, DP_PORT_VF);

	ip_addr = RTE_IPV4(172, 35, 2, 4);
	port_id = dp_get_next_avail_vf_id(&dp_layer, DP_PORT_VF);
	setup_lpm(port_id, machine_id, vni, rte_eth_dev_socket_id(port_id));
	dp_set_dhcp_range_ip4(port_id, ip_addr, 32, rte_eth_dev_socket_id(port_id));
	dp_add_route(port_id, vni, 0, ip_addr, NULL, 32, rte_eth_dev_socket_id(port_id));
	dp_start_interface(&pf_port, DP_PORT_VF);

	ip_addr = RTE_IPV4(192, 168, 129, 0);
	inet_pton(AF_INET6, "2a10:afc0:e01f:209::", trgt_ip6);
	dp_add_route(DP_PF_PORT, vni, t_vni, ip_addr, trgt_ip6, 24, rte_eth_dev_socket_id(port_id)); */

	
	/* Launch per-lcore init on every worker lcore */
	rte_eal_mp_remote_launch(graph_main_loop, NULL, SKIP_MAIN);

	/* Launch timer loop on main core */
	main_core_loop();

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

static int dp_port_prepare(dp_port_type type, int port_id, 
						   struct dp_port_ext *port_ext)
{
	struct dp_port *dp_port;

	dp_port = dp_port_create(&dp_layer, type);
	if (dp_port){
		dp_port_init(dp_port, port_id, port_ext);
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
	udp_spec.hdr.dst_port = htons(u_conf->dst_port);
	udp_mask.hdr.dst_port = 0xffff;
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

int dp_init_interface(struct dp_port_ext *port, dp_port_type type)
{
	uint32_t ret, cnt = 0;
	uint16_t nr_ports, port_id;;
	struct dp_port_ext dp_port_ext;
	char ifname[IF_NAMESIZE] = {0};

	nr_ports = rte_eth_dev_count_avail();
	if (nr_ports == 0)
		rte_exit(EXIT_FAILURE, ":: no Ethernet ports found\n");

	dp_port_ext = *port;
	printf("Looking for VFs of PF %s \n", dp_port_ext.port_name);

	RTE_ETH_FOREACH_DEV(port_id) {
		struct rte_eth_dev_info dev_info;

		ret = rte_eth_dev_info_get(port_id, &dev_info);
		if (ret != 0)
			rte_exit(EXIT_FAILURE,
					"Error during getting device (port %u) info: %s\n",
					port_id, strerror(-ret));

		if_indextoname(dev_info.if_index, ifname);
		if ((type == DP_PORT_PF) && (strncmp(dp_port_ext.port_name, ifname, IF_NAMESIZE) == 0)) {
			dp_port_flow_isolate(port_id);
			dp_port_prepare(type, port_id, &dp_port_ext);
			dp_add_pf_port_id(port_id);
			return port_id;
		}

		if ((type == DP_PORT_VF) && 
			(strstr(ifname, dp_port_ext.port_name) != NULL)) {
			if (cnt == last_assigned_vf_idx) {
				dp_port_prepare(type, port_id, &dp_port_ext);
				last_assigned_vf_idx++;
				return port_id;
			}
			cnt++;
		}	
	}
	return -1;
}

int dp_init_graph()
{
	struct rte_node_register *rx_node, *tx_node, *arp_node, *ipv6_encap_node;
	struct rte_node_register *dhcp_node, *l2_decap_node, *ipv6_nd_node;
	struct rte_node_register *dhcpv6_node;
	struct ethdev_tx_node_main *tx_node_data;
	char name[RTE_NODE_NAMESIZE];
	const char *next_nodes = name;
	struct rx_node_config rx_cfg;
	struct rx_periodic_node_config rx_periodic_cfg;
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
	dhcpv6_node = dhcpv6_node_get();

	rx_periodic_cfg.periodic_msg_queue = dp_layer.periodic_msg_queue;
	//rx_periodic_cfg.queue_id = 0;
	ret = config_rx_periodic_node(&rx_periodic_cfg);


	for (i = 0; i < dp_layer.dp_port_cnt; i++) {
		snprintf(name, sizeof(name), "%u-%u", dp_layer.ports[i]->dp_port_id, 0);
		/* Clone a new rx node with same edges as parent */
		id = rte_node_clone(rx_node->id, name);
		if (id == RTE_NODE_ID_INVALID)
			return -EIO;
		rx_cfg.port_id = dp_layer.ports[i]->dp_port_id;
		rx_cfg.queue_id = 0;
		rx_cfg.node_id = id;
		rx_cfg.grpc_queue = dp_layer.grpc_queue;
		ret = config_rx_node(&rx_cfg);

		snprintf(name, sizeof(name), "%u", dp_layer.ports[i]->dp_port_id);
		id = rte_node_clone(tx_node->id, name);
		tx_node_data->nodes[dp_layer.ports[i]->dp_port_id] = id;
		tx_node_data->port_ids[dp_layer.ports[i]->dp_port_id] = dp_layer.ports[i]->dp_port_id;

		snprintf(name, sizeof(name), "tx-%u", dp_layer.ports[i]->dp_port_id);
		if (dp_layer.ports[i]->dp_p_type == DP_PORT_VF) {
			rte_node_edge_update(arp_node->id, RTE_EDGE_ID_INVALID,
						&next_nodes, 1);
			ret = arp_set_next(
				dp_layer.ports[i]->dp_port_id, rte_node_edge_count(arp_node->id) - 1);
			if (ret < 0)
				return ret;
			rte_node_edge_update(ipv6_nd_node->id, RTE_EDGE_ID_INVALID,
						&next_nodes, 1);
			ret = ipv6_nd_set_next(
				dp_layer.ports[i]->dp_port_id, rte_node_edge_count(ipv6_nd_node->id) - 1);
			if (ret < 0)
				return ret;
			rte_node_edge_update(dhcp_node->id, RTE_EDGE_ID_INVALID,
			&next_nodes, 1);
			ret = dhcp_set_next(
				dp_layer.ports[i]->dp_port_id, rte_node_edge_count(dhcp_node->id) - 1);
			if (ret < 0)
				return ret;
			rte_node_edge_update(dhcpv6_node->id, RTE_EDGE_ID_INVALID,
			&next_nodes, 1);
			ret = dhcpv6_set_next(
				dp_layer.ports[i]->dp_port_id, rte_node_edge_count(dhcpv6_node->id) - 1);
			if (ret < 0)
				return ret;
			rte_node_edge_update(l2_decap_node->id, RTE_EDGE_ID_INVALID,
			&next_nodes, 1);
			ret = l2_decap_set_next(
				dp_layer.ports[i]->dp_port_id, rte_node_edge_count(l2_decap_node->id) - 1);
			if (ret < 0)
				return ret;
		}

		if (dp_layer.ports[i]->dp_p_type == DP_PORT_PF) {
			rte_node_edge_update(ipv6_encap_node->id, RTE_EDGE_ID_INVALID,
			&next_nodes, 1);
			ret = ipv6_encap_set_next(
				dp_layer.ports[i]->dp_port_id, rte_node_edge_count(ipv6_encap_node->id) - 1);
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

 __rte_always_inline struct underlay_conf *get_underlay_conf()
 {
	return &gen_conf;
}

 __rte_always_inline void set_underlay_conf(struct underlay_conf *u_conf)
 {
	gen_conf = *u_conf;
}

void dp_start_interface(struct dp_port_ext *port_ext, dp_port_type type)
{
	int port_id;
	port_id = dp_port_allocate(&dp_layer, port_ext, type);
	if (port_id < 0) {
		printf("Can not allocate port\n ");
		return;
	}
	if (type == DP_PORT_PF)
		dp_install_isolated_mode(port_id);
}

struct dp_dpdk_layer *get_dpdk_layer()
{
	return &dp_layer;
}

pthread_t *dp_get_ctrl_thread_id()
{
	return &ctrl_thread_tid;
}
