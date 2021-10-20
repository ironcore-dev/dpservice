#include "dpdk_layer.h"

static struct dp_dpdk_layer dp_layer;

int dp_dpdk_init(int argc, char **argv)
{
	int ret;

	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_panic("Cannot init EAL\n");

	memset(&dp_layer, 0, sizeof(struct dp_dpdk_layer));

	dp_layer.rte_mempool = rte_pktmbuf_pool_create("mbuf_pool", 16*4096-1, 128, 0,
												   RTE_MBUF_DEFAULT_BUF_SIZE,
												   rte_socket_id());
	if (dp_layer.rte_mempool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot init mbuf pool\n");

	dp_layer.nr_rx_queues = DP_NR_RX_QUEUES;
	dp_layer.nr_tx_queues = DP_NR_TX_QUEUES;

	dp_init_handler(DP_ARP_HANDLER);

	return ret;
}

static inline void print_ether_addr(const char *what, struct rte_ether_addr *eth_addr)
{
        char buf[RTE_ETHER_ADDR_FMT_SIZE];
        rte_ether_format_addr(buf, RTE_ETHER_ADDR_FMT_SIZE, eth_addr);
        printf("%s%s", what, buf);
}

static void dp_dpdk_process(struct dp_port* port)
{
	struct rte_mbuf *mbufs[32];
	struct rte_ether_hdr *eth_hdr;
	struct handler_ctx* ctx;
	unsigned int counter = 1;
	uint16_t nb_rx;
	uint16_t i = 0, j;

	for (uint16_t q=0; q < dp_layer.dp_port_cnt; q++) {
		nb_rx = rte_eth_rx_burst(port->dp_port_id, i, mbufs, 32);
		if (nb_rx) {
			for (j = 0; j < nb_rx; j++) {
				struct rte_mbuf *m = mbufs[j];

				printf("#%d (port: %d - queue: %d): Packet received", counter++, port->dp_port_id, q);
				eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
				print_ether_addr(" - src=", &eth_hdr->s_addr);
				print_ether_addr(" - dst=", &eth_hdr->d_addr);
				printf(" - ethertype=0x%04x",  ntohs(eth_hdr->ether_type));
				/* TODO Loop through all handlers */
				ctx = port->handlers[0]->ctx; 
				port->handlers[0]->ops->process_packet(ctx, m);
				rte_pktmbuf_free(m);
			}
		}
	}	
}


int dp_dpdk_main_loop()
{
	int i;

	printf("DPDK main loop started\n ");	
	
	while (true) {
		for (i = 0; i < dp_layer.dp_port_cnt; i++)
		{
			if (dp_layer.ports[i]->dp_allocated &&
				(dp_layer.ports[i]->dp_p_type = DP_PORT_VF))
					dp_dpdk_process(dp_layer.ports[i]);
		}
	}

	return 0;
}

void dp_dpdk_exit()
{
	/* TODO Free dynamically allocated ports !*/
	rte_eal_cleanup();
}

static int dp_port_prepare(dp_port_type type, int p_port_id, int port_id, 
						   struct dp_port_ext *port_ext)
{
	struct dp_port *dp_port;

	dp_port = dp_port_create(&dp_layer, type);
	if (dp_port){
		dp_port_init(dp_port, p_port_id, port_id, port_ext);
		dp_layer.ports[dp_layer.dp_port_cnt++] = dp_port;
	}

	return 0;	
} 

static int dp_initialize_vfs(struct dp_port_ext *ports, int port_count)
{
	uint32_t ret, cnt, pf_port_id = 0;
	uint16_t nr_ports;
	struct dp_port_ext dp_port_ext;
	char ifname[IF_NAMESIZE] = {0};
	char ifname_v[IF_NAMESIZE + 1] = {0};

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
				dp_port_prepare(DP_PORT_PF, pf_port_id, port_id, &dp_port_ext);
			}	

			snprintf(ifname_v, sizeof(ifname_v), "%s_", dp_port_ext.port_name);
			if (strstr(ifname, ifname_v) != NULL)
				dp_port_prepare(DP_PORT_VF, pf_port_id, port_id, &dp_port_ext);
		}
	}	
	return 0;
}

int dp_prepare(struct dp_port_ext *ports, int port_count)
{
	/* TODO setunderlay and configure uplink will be done. Parameter should be struct config */
	return dp_initialize_vfs(ports, port_count);
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
	struct port_handler* p_handler;

	p_handler = dp_create_handler(DP_ARP_HANDLER);
	dp_port_add_handler(p_handler, port_id, &dp_layer);

	return 0;
}
