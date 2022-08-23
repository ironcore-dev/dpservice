#include "dp_port.h"
#include "dp_lpm.h"
#include "dp_util.h"
#include "dp_netlink.h"

/* Ethernet port configured with default settings. 8< */
struct rte_eth_conf port_conf = {
	.rxmode = {
			.mq_mode = ETH_MQ_RX_NONE,
		.split_hdr_size = 0,
	},
	.txmode = {
			.offloads =
				DEV_TX_OFFLOAD_IPV4_CKSUM  |
				DEV_TX_OFFLOAD_UDP_CKSUM   |
				DEV_TX_OFFLOAD_TCP_CKSUM   |
				DEV_TX_OFFLOAD_IP_TNL_TSO
	},
	.rx_adv_conf = {
			.rss_conf = {
					.rss_key = NULL,
					.rss_hf = ETH_RSS_IP,
					},
					},
	.intr_conf = {
		.lsc = 1, /**< lsc interrupt feature enabled */
	},
};

struct dp_port *dp_port_create(struct dp_dpdk_layer *dp_layer, dp_port_type type)
{
	struct dp_port *port;

	port = malloc(sizeof(struct dp_port));
	if (!port)
		return NULL;

	memset(port, 0, sizeof(struct dp_port));
	port->dp_layer = dp_layer;
	port->dp_allocated = 0;
	port->dp_p_type = type;

	return port;
}


int dp_port_init(struct dp_port *port, int port_id, struct dp_port_ext *port_details)
{
	struct rte_ether_addr pf_neigh_mac;
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

	if (port->dp_p_type == DP_PORT_VF)
		ret = rte_eth_dev_configure(port_id,
								port->dp_layer->nr_std_rx_queues + port->dp_layer->nr_vf_hairpin_rx_tx_queues,
								port->dp_layer->nr_std_tx_queues + port->dp_layer->nr_vf_hairpin_rx_tx_queues, &port_conf);
	else
		ret = rte_eth_dev_configure(port_id,
								port->dp_layer->nr_std_rx_queues + port->dp_layer->nr_pf_hairpin_rx_tx_queues,
								port->dp_layer->nr_std_tx_queues + port->dp_layer->nr_pf_hairpin_rx_tx_queues, &port_conf);

	if (ret < 0) {
		rte_exit(EXIT_FAILURE,
				":: cannot configure device: err=%d, port=%u\n",
				ret, port_id);
	}

	rxq_conf = dev_info.default_rxconf;
	rxq_conf.offloads = port_conf.rxmode.offloads;
	/* >8 End of ethernet port configured with default settings. */

	/* Configuring number of RX and TX queues connected to single port. 8< */
	for (i = 0; i < port->dp_layer->nr_std_rx_queues; i++) {
		ret = rte_eth_rx_queue_setup(port_id, i, 1024,
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

	for (i = 0; i < port->dp_layer->nr_std_tx_queues; i++) {
		ret = rte_eth_tx_queue_setup(port_id, i, 2048,
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
		printf("Setting interface number %d in promiscuous mode\n", port_id);
		if (ret != 0)
			rte_exit(EXIT_FAILURE,
					":: promiscuous mode enable failed: err=%s, port=%u\n",
					rte_strerror(-ret), port_id);
	}

	dp_set_mac(port_id);

	if (port->dp_p_type == DP_PORT_PF) {
		dp_get_pf_neigh_mac(dev_info.if_index, &pf_neigh_mac, dp_get_mac(port_id));
		dp_set_neigh_mac(port_id, &pf_neigh_mac);
	}

	if (port->dp_p_type == DP_PORT_VF)
		memcpy(port->vf_name, ifname, IF_NAMESIZE);
	port->dp_port_id = port_id;
	port->dp_port_ext = *port_details;
	return 0;
}

void print_link_info(int port_id, char *out, size_t out_size)
{
	struct rte_eth_stats stats;
	struct rte_ether_addr mac_addr;
	struct rte_eth_link eth_link;
	uint16_t mtu;
	int ret;

	memset(&stats, 0, sizeof(stats));
	rte_eth_stats_get(port_id, &stats);

	ret = rte_eth_macaddr_get(port_id, &mac_addr);
	if (ret != 0) {
		snprintf(out, out_size, "\n%d: MAC address get failed: %s",
			 port_id, rte_strerror(-ret));
		return;
	}

	ret = rte_eth_link_get(port_id, &eth_link);
	if (ret < 0) {
		snprintf(out, out_size, "\n%d: link get failed: %s",
			 port_id, rte_strerror(-ret));
		return;
	}

	rte_eth_dev_get_mtu(port_id, &mtu);

	snprintf(out, out_size,
		"\n"
		"%s: flags=<%s> mtu %u\n"
		"\tether %02X:%02X:%02X:%02X:%02X:%02X rxqueues %u txqueues %u\n"
		"\tport# %u  speed %s\n"
		"\tRX packets %" PRIu64"  bytes %" PRIu64"\n"
		"\tRX errors %" PRIu64"  missed %" PRIu64"  no-mbuf %" PRIu64"\n"
		"\tTX packets %" PRIu64"  bytes %" PRIu64"\n"
		"\tTX errors %" PRIu64"\n",
		"pf0",
		eth_link.link_status == 0 ? "DOWN" : "UP",
		mtu,
		mac_addr.addr_bytes[0], mac_addr.addr_bytes[1],
		mac_addr.addr_bytes[2], mac_addr.addr_bytes[3],
		mac_addr.addr_bytes[4], mac_addr.addr_bytes[5],
		1,
		1,
		port_id,
		rte_eth_link_speed_to_str(eth_link.link_speed),
		stats.ipackets,
		stats.ibytes,
		stats.ierrors,
		stats.imissed,
		stats.rx_nombuf,
		stats.opackets,
		stats.obytes,
		stats.oerrors);
}

int dp_get_pf_port_id_with_name(struct dp_dpdk_layer *dp_layer, char *pf_name)
{
	int i;

	for (i = 0; i < dp_layer->dp_port_cnt; i++) {
		if ((strncmp(dp_layer->ports[i]->dp_port_ext.port_name, pf_name, IF_NAMESIZE) == 0) &&
			dp_layer->ports[i]->dp_p_type == DP_PORT_PF)
			return dp_layer->ports[i]->dp_port_id;
	}
	return -1;
}


struct dp_port *dp_get_next_avail_vf_port(struct dp_dpdk_layer *dp_layer, dp_port_type type)
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

static struct dp_port *dp_get_alloced_vf_port_per_id(struct dp_dpdk_layer *dp_layer, int portid)
{
	int i;

	/* Find the corresponding internal vf port structure */
	for (i = 0; i < dp_layer->dp_port_cnt; i++) {
		if (dp_layer->ports[i]->dp_allocated &&
			 (dp_layer->ports[i]->dp_port_id == portid))
			return dp_layer->ports[i];
	}

	return NULL;
}

struct dp_port *dp_get_vf_port_per_id(struct dp_dpdk_layer *dp_layer, int portid)
{
	int i;

	/* Find the corresponding internal vf port structure */
	for (i = 0; i < dp_layer->dp_port_cnt; i++)
		if (dp_layer->ports[i]->dp_port_id == portid)
			return dp_layer->ports[i];

	return NULL;
}

bool dp_is_port_allocated(struct dp_dpdk_layer *dp_layer, int portid)
{
	struct dp_port *vf_port = dp_get_vf_port_per_id(dp_layer, portid);

	if (!vf_port)
		return true;

	return (vf_port->dp_allocated != 0);
}

int dp_port_deallocate(struct dp_dpdk_layer *dp_layer, int portid)
{
	struct dp_port *vf_port = dp_get_alloced_vf_port_per_id(dp_layer, portid);

	if (!vf_port)
		return 0;

	vf_port->dp_allocated = 0;

	return 1;
}

int dp_port_allocate(struct dp_dpdk_layer *dp_layer, int portid, struct dp_port_ext *port_ext, dp_port_type type)
{
	struct dp_port *vf_port;
	int port_id = -1, ret;

	if (type == DP_PORT_PF) {
		port_id = dp_get_pf_port_id_with_name(dp_layer, port_ext->port_name);
	} else {
		vf_port = dp_get_vf_port_per_id(dp_layer, portid);
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

void dp_port_exit(void)
{

}
