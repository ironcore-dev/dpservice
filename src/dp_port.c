#include "dp_error.h"
#include "dp_hairpin.h"
#include "dp_log.h"
#include "dp_lpm.h"
#include "dp_netlink.h"
#include "dp_port.h"
#ifdef ENABLE_VIRTSVC
#	include "dp_virtsvc.h"
#endif
#include "monitoring/dp_event.h"
#include "nodes/rx_node.h"
#include "rte_flow/dp_rte_flow_init.h"

const struct rte_eth_conf port_conf_default = {
	.rxmode = {
		.mq_mode = RTE_ETH_MQ_RX_NONE,
	},
	.txmode = {
		.offloads =
			RTE_ETH_TX_OFFLOAD_IPV4_CKSUM |
			RTE_ETH_TX_OFFLOAD_UDP_CKSUM |
			RTE_ETH_TX_OFFLOAD_TCP_CKSUM |
			RTE_ETH_TX_OFFLOAD_IP_TNL_TSO
	},
	.rx_adv_conf = {
		.rss_conf = {
			.rss_key = NULL,
			.rss_hf = RTE_ETH_RSS_IP,
		},
	},
	.intr_conf = {
		.lsc = 1, /**< lsc interrupt feature enabled */
	},
};

static uint16_t pf_ports[DP_MAX_PF_PORTS];
static struct dp_ports dp_ports;

struct dp_ports *get_dp_ports()
{
	return &dp_ports;
}

static void dp_port_init_pf_table()
{
	for (int i = 0; i < DP_MAX_PF_PORTS; ++i)
		pf_ports[i] = DP_INVALID_PORT_ID;
}

uint16_t dp_port_get_pf0_id()
{
	return pf_ports[0];
}

uint16_t dp_port_get_pf1_id()
{
	return pf_ports[1];
}

bool dp_port_is_pf(uint16_t port_id)
{
	if (port_id == DP_INVALID_PORT_ID)
		return false;
	for (int i = 0; i < DP_MAX_PF_PORTS; ++i)
		if (pf_ports[i] == port_id)
			return true;
	return false;
}

static int dp_port_register_pf(uint16_t port_id)
{
	for (int i = 0; i < DP_MAX_PF_PORTS; ++i) {
		if (pf_ports[i] == DP_INVALID_PORT_ID) {
			pf_ports[i] = port_id;
			return DP_OK;
		}
	}
	DPS_LOG_ERR("To many physical ports", DP_LOG_MAX(DP_MAX_PF_PORTS));
	return DP_ERROR;
}


static inline struct dp_port *get_port(uint16_t port_id)
{
	DP_FOREACH_PORT(&dp_ports, port)
		if (port->port_id == port_id)
			return port;
	return NULL;
}

struct dp_port *dp_port_get(uint16_t port_id)
{
	struct dp_port *port = get_port(port_id);

	if (!port)
		DPS_LOG_ERR("Port not registered in dp-service", DP_LOG_PORTID(port_id));

	return port;
}

struct dp_port *dp_port_get_vf(uint16_t port_id)
{
	struct dp_port *port = get_port(port_id);

	if (!port || port->port_type != DP_PORT_VF) {
		DPS_LOG_ERR("VF port not registered in dp-service", DP_LOG_PORTID(port_id));
		return NULL;
	}

	return port;
}

int dp_port_set_link_status(uint16_t port_id, uint8_t status)
{
	struct dp_port *port = dp_port_get(port_id);

	if (!port)
		return DP_ERROR;

	port->link_status = status;
	return DP_OK;
}

uint8_t dp_port_get_link_status(uint16_t port_id)
{
	struct dp_port *port = get_port(port_id);

	if (!port)
		return RTE_ETH_LINK_DOWN;

	return port->link_status;
}

int dp_port_set_vf_attach_status(uint16_t port_id, enum dp_vf_port_attach_status status)
{
	struct dp_port *port = dp_port_get_vf(port_id);

	if (!port)
		return DP_ERROR;

	port->attach_status = status;
	return DP_OK;
}

enum dp_vf_port_attach_status dp_port_get_vf_attach_status(uint16_t port_id)
{
	struct dp_port *port = get_port(port_id);

	if (!port || port->port_type != DP_PORT_VF)
		return DP_VF_PORT_DETACHED;

	return port->attach_status;
}

bool dp_port_is_vf_free(uint16_t port_id)
{
	struct dp_port *port = get_port(port_id);

	return port && port->port_type == DP_PORT_VF && !port->allocated;
}


static int dp_port_init_ethdev(uint16_t port_id, struct rte_eth_dev_info *dev_info, enum dp_port_type port_type)
{
	struct dp_dpdk_layer *dp_layer = get_dpdk_layer();
	struct rte_ether_addr pf_neigh_mac;
	struct rte_eth_txconf txq_conf;
	struct rte_eth_rxconf rxq_conf;
	struct rte_eth_conf port_conf = port_conf_default;
	uint16_t nr_hairpin_queues;
	int ret;

	/* Default config */
	port_conf.txmode.offloads &= dev_info->tx_offload_capa;

	nr_hairpin_queues = port_type == DP_PORT_VF
		? DP_NR_VF_HAIRPIN_RX_TX_QUEUES
		: (DP_NR_PF_HAIRPIN_RX_TX_QUEUES + DP_NR_VF_HAIRPIN_RX_TX_QUEUES * dp_layer->num_of_vfs);
	ret = rte_eth_dev_configure(port_id,
								DP_NR_STD_RX_QUEUES + nr_hairpin_queues,
								DP_NR_STD_TX_QUEUES + nr_hairpin_queues,
								&port_conf);
	if (DP_FAILED(ret)) {
		DPS_LOG_ERR("Cannot configure ethernet device", DP_LOG_PORTID(port_id), DP_LOG_RET(ret));
		return DP_ERROR;
	}

	rxq_conf = dev_info->default_rxconf;
	rxq_conf.offloads = port_conf.rxmode.offloads;

	/* RX and TX queues config */
	for (int i = 0; i < DP_NR_STD_RX_QUEUES; ++i) {
		ret = rte_eth_rx_queue_setup(port_id, i, 1024,
									 rte_eth_dev_socket_id(port_id),
									 &rxq_conf,
									 dp_layer->rte_mempool);
		if (DP_FAILED(ret)) {
			DPS_LOG_ERR("Rx queue setup failed", DP_LOG_PORTID(port_id), DP_LOG_RET(ret));
			return DP_ERROR;
		}
	}

	txq_conf = dev_info->default_txconf;
	txq_conf.offloads = port_conf.txmode.offloads;

	for (int i = 0; i < DP_NR_STD_TX_QUEUES; ++i) {
		ret = rte_eth_tx_queue_setup(port_id, i, 2048,
									 rte_eth_dev_socket_id(port_id),
									 &txq_conf);
		if (DP_FAILED(ret)) {
			DPS_LOG_ERR("Tx queue setup failed", DP_LOG_PORTID(port_id), DP_LOG_RET(ret));
			return DP_ERROR;
		}
	}

	/* dp-service specific config */
	if (port_type == DP_PORT_VF) {
		DPS_LOG_INFO("INIT setting port to promiscuous mode", DP_LOG_PORTID(port_id));
		ret = rte_eth_promiscuous_enable(port_id);
		if (DP_FAILED(ret)) {
			DPS_LOG_ERR("Promiscuous mode setting failed", DP_LOG_PORTID(port_id), DP_LOG_RET(ret));
			return DP_ERROR;
		}
	}

	dp_set_mac(port_id);

	if (port_type == DP_PORT_PF) {
		if (DP_FAILED(dp_get_pf_neigh_mac(dev_info->if_index, &pf_neigh_mac, dp_get_mac(port_id))))
			return DP_ERROR;
		dp_set_neigh_mac(port_id, &pf_neigh_mac);
	}

	return DP_OK;
}

static int dp_port_flow_isolate(uint16_t port_id)
{
	struct rte_flow_error error;
	int ret;

	/* Poisoning to make sure PMDs update it in case of error. */
	memset(&error, 0x66, sizeof(error));
	error.message = "(null)";

	ret = rte_flow_isolate(port_id, 1, &error);
	if (DP_FAILED(ret)) {
		DPS_LOG_ERR("Flows cannot be isolated", DP_LOG_PORTID(port_id), DP_LOG_FLOW_ERROR(error.message), DP_LOG_RET(ret));
		return ret;
	}
	DPS_LOG_INFO("Ingress traffic on port is now restricted to the defined flow rules", DP_LOG_PORTID(port_id));
	return DP_OK;
}

static struct dp_port *dp_port_init_interface(uint16_t port_id, struct rte_eth_dev_info *dev_info, enum dp_port_type type)
{
	static int last_pf1_hairpin_tx_rx_queue_offset = 1;
	struct dp_port *port;
	int ret;

	if (type == DP_PORT_PF) {
		if (DP_FAILED(dp_port_register_pf(port_id)))
			return NULL;
		if (dp_conf_get_nic_type() != DP_CONF_NIC_TYPE_TAP)
			if (DP_FAILED(dp_port_flow_isolate(port_id)))
				return NULL;
	}

	if (DP_FAILED(dp_port_init_ethdev(port_id, dev_info, type)))
		return NULL;

	// oveflow check done by liming the number of calls to this function
	port = dp_ports.end++;
	port->port_type = type;
	port->port_id = port_id;

	switch (type) {
	case DP_PORT_PF:
		ret = rte_eth_dev_callback_register(port_id, RTE_ETH_EVENT_INTR_LSC, dp_link_status_change_event_callback, NULL);
		if (DP_FAILED(ret)) {
			DPS_LOG_ERR("Cannot register link status callback", DP_LOG_RET(ret));
			return NULL;
		}
		break;
	case DP_PORT_VF:
		// All VFs belong to pf0, assign a tx queue from pf1 for it
		if (dp_conf_is_offload_enabled()) {
			port->peer_pf_port_id = dp_port_get_pf1_id();
			port->peer_pf_hairpin_tx_rx_queue_offset = last_pf1_hairpin_tx_rx_queue_offset++;
			if (last_pf1_hairpin_tx_rx_queue_offset > UINT8_MAX) {
				DPS_LOG_ERR("Too many VFs, cannot create more hairpins");
				return NULL;
			}
		}
		// No link status callback, VFs are not critical for cross-hypervisor communication
		break;
	}
	return port;
}

static int dp_port_set_up_hairpin(void)
{

	DP_FOREACH_PORT(&dp_ports, port) {
		if (port->port_type == DP_PORT_PF) {
			port->peer_pf_port_id = \
					port->port_id == dp_port_get_pf0_id() ? dp_port_get_pf1_id() : dp_port_get_pf0_id();

			port->peer_pf_hairpin_tx_rx_queue_offset = 1;
		}

		if (DP_FAILED(dp_hairpin_setup(port)))
				return DP_ERROR;
	}

	return DP_OK;
}

static int dp_port_init_pf(const char *pf_name)
{
	uint16_t port_id;
	struct rte_eth_dev_info dev_info;
	char ifname[IFNAMSIZ] = {0};
	struct dp_port *port;

	RTE_ETH_FOREACH_DEV(port_id) {
		if (DP_FAILED(dp_get_dev_info(port_id, &dev_info, ifname)))
			return DP_ERROR;
		if (!strncmp(pf_name, ifname, sizeof(ifname))) {
			DPS_LOG_INFO("INIT initializing PF port", DP_LOG_PORTID(port_id), DP_LOG_IFNAME(ifname));
			port = dp_port_init_interface(port_id, &dev_info, DP_PORT_PF);
			if (!port)
				return DP_ERROR;
			snprintf(port->port_name, sizeof(port->port_name), "%s", pf_name);
			return DP_OK;
		}
	}
	DPS_LOG_ERR("No such PF", DP_LOG_NAME(pf_name));
	return DP_ERROR;
}

static int dp_port_init_vfs(const char *vf_pattern, int num_of_vfs)
{
	uint16_t port_id;
	struct rte_eth_dev_info dev_info;
	char ifname[IFNAMSIZ] = {0};
	uint32_t vf_count = 0;
	struct dp_port *port;

	RTE_ETH_FOREACH_DEV(port_id) {
		if (DP_FAILED(dp_get_dev_info(port_id, &dev_info, ifname)))
			return DP_ERROR;
		if (strstr(ifname, vf_pattern) && ++vf_count <= num_of_vfs) {
			DPS_LOG_INFO("INIT initializing VF port", DP_LOG_PORTID(port_id), DP_LOG_IFNAME(ifname));
			port = dp_port_init_interface(port_id, &dev_info, DP_PORT_VF);
			if (!port)
				return DP_ERROR;
			snprintf(port->port_name, sizeof(port->port_name), "%s", vf_pattern);
			snprintf(port->vf_name, sizeof(port->vf_name), "%s", ifname);
		}
	}
	if (!vf_count) {
		DPS_LOG_ERR("No such VF", DP_LOG_NAME(vf_pattern));
		return DP_ERROR;
	} else if (vf_count < num_of_vfs) {
		DPS_LOG_ERR("Not all VFs initialized", DP_LOG_VALUE(vf_count), DP_LOG_MAX(num_of_vfs));
		return DP_ERROR;
	}
	return DP_OK;
}

int dp_ports_init()
{
	int num_of_vfs = get_dpdk_layer()->num_of_vfs;
	int num_of_ports = DP_MAX_PF_PORTS + num_of_vfs;

	dp_port_init_pf_table();
	dp_ports.ports = (struct dp_port *)calloc(num_of_ports, sizeof(struct dp_port));
	if (!dp_ports.ports) {
		DPS_LOG_ERR("Cannot allocate port table");
		return DP_ERROR;
	}
	dp_ports.end = dp_ports.ports;

	// these need to be done in order
	if (DP_FAILED(dp_port_init_pf(dp_conf_get_pf0_name()))
		|| DP_FAILED(dp_port_init_pf(dp_conf_get_pf1_name()))
		|| DP_FAILED(dp_port_init_vfs(dp_conf_get_vf_pattern(), num_of_vfs)))
		return DP_ERROR;

	if (dp_conf_is_offload_enabled()) {
		if (DP_FAILED(dp_port_set_up_hairpin()))
			return DP_ERROR;
	}

	return DP_OK;
}

void dp_ports_free()
{
	free(dp_ports.ports);
}


static int dp_port_install_isolated_mode(int port_id)
{
	DPS_LOG_INFO("Init isolation flow rule for IPinIP tunnels");
	if (DP_FAILED(dp_install_isolated_mode_ipip(port_id, DP_IP_PROTO_IPv4_ENCAP))
		|| DP_FAILED(dp_install_isolated_mode_ipip(port_id, DP_IP_PROTO_IPv6_ENCAP)))
		return DP_ERROR;
#ifdef ENABLE_VIRTSVC
	return dp_virtsvc_install_isolation_rules(port_id);
#else
	return DP_OK;
#endif
}

static int dp_port_bind_port_hairpins(struct dp_port *port)
{
	// two pf port's hairpins are bound when processing the second port
	if (port->port_id == dp_port_get_pf0_id())
		return DP_OK;

	if (DP_FAILED(dp_hairpin_bind(port)))
		return DP_ERROR;

	return DP_OK;
}

int dp_port_start(uint16_t port_id)
{
	struct dp_port *port;
	int ret;

	port = dp_port_get(port_id);
	if (!port)
		return DP_ERROR;

	ret = rte_eth_dev_start(port_id);
	if (DP_FAILED(ret)) {
		DPS_LOG_ERR("Cannot start ethernet port", DP_LOG_PORTID(port_id), DP_LOG_RET(ret));
		return DP_ERROR;
	}

	if (DP_FAILED(rx_node_set_enabled(port_id, true)))
		return DP_ERROR;

	port->link_status = RTE_ETH_LINK_UP;
	port->allocated = true;

	if (port->port_type == DP_PORT_PF && dp_conf_get_nic_type() != DP_CONF_NIC_TYPE_TAP) {
		if (dp_conf_is_offload_enabled()) {
			if (DP_FAILED(dp_port_bind_port_hairpins(port)))
				return DP_ERROR;
		}
		// first, finish pf-pf hairpin binding, then install isolation rules
		if (port_id == dp_port_get_pf1_id()) {
			if (DP_FAILED(dp_port_install_isolated_mode(dp_port_get_pf0_id())))
				return DP_ERROR;
			if (DP_FAILED(dp_port_install_isolated_mode(dp_port_get_pf1_id())))
				return DP_ERROR;
		}
	}

	return DP_OK;
}

int dp_port_stop(uint16_t port_id)
{
	struct dp_port *port;
	int ret;

	port = dp_port_get(port_id);
	if (!port)
		return DP_ERROR;

	// TODO(plague): research - no need to tear down hairpins?

	if (DP_FAILED(rx_node_set_enabled(port_id, false)))
		return DP_ERROR;

	/* Tap interfaces in test environment can not be stopped */
	/* due to a bug in dpdk tap device library. */
	if (dp_conf_get_nic_type() != DP_CONF_NIC_TYPE_TAP) {
		ret = rte_eth_dev_stop(port_id);
		if (DP_FAILED(ret)) {
			DPS_LOG_ERR("Cannot stop ethernet port", DP_LOG_PORTID(port_id), DP_LOG_RET(ret));
			return DP_ERROR;
		}
	}

	port->allocated = false;
	return DP_OK;
}
