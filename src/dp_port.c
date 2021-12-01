#include "dp_port.h"
#include "dp_lpm.h"

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
				DEV_TX_OFFLOAD_OUTER_UDP_CKSUM| 
				DEV_TX_OFFLOAD_TCP_TSO,
	},
	.rx_adv_conf = {
			.rss_conf = {
					.rss_key = NULL,
					.rss_hf = ETH_RSS_IP,
					},
					},
};

#define DP_IPV6_MASK 64

/*TODO This should come from netlink */
static struct rte_ether_addr pf_neigh_mac = 
								{.addr_bytes[0] = 0x90,
								.addr_bytes[1] = 0x3c,
								.addr_bytes[2] = 0xb3,
								.addr_bytes[3] = 0x33,
								.addr_bytes[4] = 0x72,
								.addr_bytes[5] = 0xfb,
								};

static uint8_t port_ip6s[DP_MAX_PORTS][16] = {
	{0xfe,0x80,0x00,0x00,0x00,0x00,0x00,0x00,0xb8,0x66,0xc7,0xff,0xfe,0xd5,0xce,0x25},
	{0xfe,0x80,0x00,0x00,0x00,0x00,0x00,0x00,0xb8,0x66,0xc7,0xff,0xfe,0xd5,0xce,0x26},
	{0x20,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0xb8,0x66,0xc7,0xff,0xfe,0xd5,0xce,0x27}
};

struct dp_port* dp_port_create(struct dp_dpdk_layer *dp_layer, dp_port_type type)
{
	struct dp_port* port;

	port = malloc(sizeof(struct dp_port));
	if (!port)
		return NULL;
	
	memset(port, 0, sizeof(struct dp_port));
	port->dp_layer = dp_layer;
	port->dp_allocated = 0;
	port->dp_p_type = type;

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
		/* Add this rx node to its graph */
		snprintf(port->node_name,
				 RTE_NODE_NAMESIZE, "ethdev_rx-%u-%u", port_id, i);
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

	if (port->dp_p_type == DP_PORT_VF) {
		ret = rte_eth_promiscuous_enable(port_id);
		if (ret != 0)
			rte_exit(EXIT_FAILURE,
					":: promiscuous mode enable failed: err=%s, port=%u\n",
					rte_strerror(-ret), port_id);
	}	

	/* TODO PF underlay mac, this should be called by neighbour discovery */
	if (port->dp_p_type == DP_PORT_PF)
		dp_set_neigh_mac (port_id, &pf_neigh_mac);

	dp_set_mac(port_id);
	dp_set_ip6(port_id, port_ip6s[port_id], DP_IPV6_MASK, rte_eth_dev_socket_id(port_id));

	if (port->dp_p_type == DP_PORT_VF)
		memcpy(port->vf_name, ifname, IF_NAMESIZE);
	port->dp_port_id = port_id;
	port->dp_port_ext = *port_details;
	return 0;
}

int dp_get_pf_port_id_with_name(struct dp_dpdk_layer *dp_layer, char* pf_name)
{
	int i;

	for (i = 0; i < dp_layer->dp_port_cnt; i++) {
		if ((strncmp(dp_layer->ports[i]->dp_port_ext.port_name, pf_name, IF_NAMESIZE) == 0) && 
			dp_layer->ports[i]->dp_p_type == DP_PORT_PF)
			return dp_layer->ports[i]->dp_port_id;
	}
	return -1;
}


struct dp_port* dp_get_next_avail_vf_port(struct dp_dpdk_layer *dp_layer, dp_port_type type)
{
	int i;

	/* Find first not allocated vfport */
	for (i = 0; i < dp_layer->dp_port_cnt; i++) {
		if ((dp_layer->ports[i]->dp_p_type == type) &&
			!dp_layer->ports[i]->dp_allocated)
			return dp_layer->ports[i];
	} 

	return NULL;
}

int dp_get_next_avail_vf_id(struct dp_dpdk_layer *dp_layer, dp_port_type type)
{
	int i;

	/* Find first not allocated vfport */
	for (i = 0; i < dp_layer->dp_port_cnt; i++) {
		if ((dp_layer->ports[i]->dp_p_type == type) &&
			!dp_layer->ports[i]->dp_allocated)
			return dp_layer->ports[i]->dp_port_id;
	} 

	return -1;
}

int dp_port_allocate(struct dp_dpdk_layer *dp_layer, struct dp_port_ext *port_ext, dp_port_type type)
{
	struct dp_port* vf_port;
	int port_id = -1, ret;

	if (type == DP_PORT_PF) {
		port_id = dp_get_pf_port_id_with_name(dp_layer, port_ext->port_name);
	} else {
		vf_port = dp_get_next_avail_vf_port(dp_layer, type);
		if (vf_port) {
			port_id = vf_port->dp_port_id;
			vf_port->dp_allocated = 1;
		} else {
			return port_id;
		}
	}
	ret = rte_eth_dev_start(port_id);
	if (ret < 0) {
		rte_exit(EXIT_FAILURE,
				"rte_eth_dev_start:err=%d, port=%u\n",
				ret, port_id);
	}
	return port_id;
}

void dp_port_exit()
{

}
