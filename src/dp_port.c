#include "dp_port.h"
#include "handlers/arp_handler.h"


/* Ethernet port configured with default settings. 8< */
struct rte_eth_conf port_conf = {
	.rxmode = {
			.mq_mode = ETH_MQ_RX_NONE,
		.split_hdr_size = 0,
	},
	.txmode = {
			.offloads =
				DEV_TX_OFFLOAD_GENEVE_TNL_TSO |
				DEV_TX_OFFLOAD_IPV4_CKSUM  |
				DEV_TX_OFFLOAD_UDP_CKSUM   |
				DEV_TX_OFFLOAD_TCP_CKSUM   |
				DEV_TX_OFFLOAD_SCTP_CKSUM  |
				DEV_TX_OFFLOAD_TCP_TSO,
	},
	.rx_adv_conf = {
			.rss_conf = {
					.rss_key = NULL,
					.rss_hf = ETH_RSS_IP,
					},
					},
};

struct dp_port* dp_port_create(struct dp_dpdk_layer *dp_layer, dp_port_type type)
{
	struct dp_port* port;

	port = malloc(sizeof(struct dp_port));
	if (!port)
		return NULL;
	
	memset(port, 0, sizeof(struct dp_port));
	port->dp_layer = dp_layer;
	port->dp_p_type = type;
	port->dp_allocated = 0;

	return port;
}


int dp_port_init(struct dp_port* port, int p_port_id, int port_id, struct dp_port_ext *port_details)
{
	char ifname[IF_NAMESIZE] = {0};
	struct rte_eth_txconf txq_conf;
	struct rte_eth_rxconf rxq_conf;
	struct rte_eth_dev_info dev_info;
	
	int ret;
	uint16_t i;

	ret = rte_eth_dev_info_get(port_id, &dev_info);
	if (ret != 0)
		rte_exit(EXIT_FAILURE,
				"Error during getting device (port %u) info: %s\n",
				port_id, strerror(-ret));

	if_indextoname(dev_info.if_index, ifname);
	printf(":: initializing port: %d (%s)\n", port_id, ifname);

	port_conf.txmode.offloads &= dev_info.tx_offload_capa;
	ret = rte_eth_dev_configure(port_id,
								port->dp_layer->nr_rx_queues, 
								port->dp_layer->nr_tx_queues, &port_conf);
	if (ret < 0) {
		rte_exit(EXIT_FAILURE,
				":: cannot configure device: err=%d, port=%u\n",
				ret, port_id);
	}

	rxq_conf = dev_info.default_rxconf;
	rxq_conf.offloads = port_conf.rxmode.offloads;
	/* >8 End of ethernet port configured with default settings. */

	/* Configuring number of RX and TX queues connected to single port. 8< */
	for (i = 0; i < port->dp_layer->nr_rx_queues; i++) {
		ret = rte_eth_rx_queue_setup(port_id, i, 512,
									rte_eth_dev_socket_id(port_id),
									&rxq_conf,
									port->dp_layer->rte_mempool);
		if (ret != 0) {
			rte_exit(EXIT_FAILURE,
					":: Rx queue setup failed: err=%d, port=%u\n",
					ret, port_id);
		}
	}

	txq_conf = dev_info.default_txconf;
	txq_conf.offloads = port_conf.txmode.offloads;

	for (i = 0; i < port->dp_layer->nr_tx_queues; i++) {
		ret = rte_eth_tx_queue_setup(port_id, i, 512,
									rte_eth_dev_socket_id(port_id),
									&txq_conf);
		if (ret != 0) {
			rte_exit(EXIT_FAILURE,
					":: Tx queue setup failed: err=%d, port=%u\n",
					ret, port_id);
		}
	}
	/* >8 End of Configuring RX and TX queues connected to single port. */

	/* Setting the RX port to promiscuous mode. 8< */
	ret = rte_eth_promiscuous_enable(port_id);
	if (ret != 0)
		rte_exit(EXIT_FAILURE,
				":: promiscuous mode enable failed: err=%s, port=%u\n",
				rte_strerror(-ret), port_id);
	/* >8 End of setting the RX port to promiscuous mode. */

	/* Starting the port. 8< */
	ret = rte_eth_dev_start(port_id);
	if (ret < 0) {
		rte_exit(EXIT_FAILURE,
				"rte_eth_dev_start:err=%d, port=%u\n",
				ret, port_id);
	}
	/* >8 End of starting the port. */
	if (port->dp_p_type == DP_PORT_VF)
		memcpy(port->vf_name, ifname, IF_NAMESIZE);
	port->dp_port_id = port_id;
	return 0;
}

struct dp_port* get_dp_vf_port_with_id(int port_id, struct dp_dpdk_layer *dp_layer)
{
	int i;

	/* Find first not allocated vfport */
	for (i = 0; i < dp_layer->dp_port_cnt; i++) {
		if (dp_layer->ports[i]->dp_p_port_id == port_id && 
			dp_layer->ports[i]->dp_p_type == DP_PORT_VF &&
			!dp_layer->ports[i]->dp_allocated)
			return dp_layer->ports[i];
	} 

	return NULL;
}

void dp_port_allocate(struct dp_port* port)
{
	port->dp_allocated = 1;
}

static struct dp_port* get_dp_port_with_id(int port_id, struct dp_dpdk_layer *dp_layer)
{
	int i;

	for (i = 0; i < dp_layer->dp_port_cnt; i++) 
		if (dp_layer->ports[i]->dp_port_id == port_id)
			return dp_layer->ports[i];

	return NULL;
} 

void dp_port_add_handler(struct port_handler* h, int port_id, struct dp_dpdk_layer *dp_layer)
{
	struct hdlr_config config;
	struct handler_ctx* ctx;
	struct dp_port* port; 
	int hdlr_cnt;

	port = get_dp_port_with_id(port_id, dp_layer);
	if (port) { 
		config.port_id = port_id;
		config.rte_mempool = dp_layer->rte_mempool;
		hdlr_cnt = port->dp_handler_cnt++;
		port->handlers[hdlr_cnt] = h;
		ctx = port->handlers[hdlr_cnt]->ctx;
		port->handlers[hdlr_cnt]->ops->set_config(ctx, &config);
	}
}  

void dp_port_exit()
{

}
