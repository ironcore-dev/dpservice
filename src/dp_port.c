#include "dp_error.h"
#include <rte_bus_pci.h>
#include "dp_conf.h"
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
#include "rte_flow/dp_rte_flow.h"
#include "rte_flow/dp_rte_flow_capture.h"
#include "monitoring/dp_graphtrace.h"

static const struct rte_eth_conf port_conf_default = {
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

struct dp_port *_dp_port_table[DP_MAX_PORTS];
struct dp_port *_dp_pf_ports[DP_MAX_PF_PORTS];
struct dp_ports _dp_ports;

static int dp_port_register_pf(struct dp_port *port)
{
	// sub-optimal, but the number of PF ports is extremely low
	// and this is only called in initialization
	for (size_t i = 0; i < RTE_DIM(_dp_pf_ports); ++i) {
		if (_dp_pf_ports[i] == NULL) {
			_dp_pf_ports[i] = port;
			return DP_OK;
		}
	}
	DPS_LOG_ERR("To many physical ports", DP_LOG_MAX(RTE_DIM(_dp_pf_ports)));
	return DP_ERROR;
}

struct dp_port *dp_get_port_by_name(const char *pci_name)
{
	uint16_t port_id;

	if (pci_name[0] == '\0' || DP_FAILED(rte_eth_dev_get_port_by_name(pci_name, &port_id)))
		return NULL;  // no error, this comes from a client

	if (port_id >= RTE_DIM(_dp_port_table)) {
		DPS_LOG_ERR("Invalid port stored for this device", DP_LOG_PCI(pci_name));
		return NULL;
	}

	return _dp_port_table[port_id];
}

int dp_attach_vf(struct dp_port *port)
{
	if (port->port_type != DP_PORT_VF) {
		DPS_LOG_ERR("VF port not registered in dpservice", DP_LOG_PORT(port));
		return DP_ERROR;
	}

	port->attached = true;
	return DP_OK;
}

static int dp_port_init_ethdev(struct dp_port *port, struct rte_eth_dev_info *dev_info, enum dp_port_type port_type)
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

	ret = rte_eth_dev_configure(port->port_id,
								DP_NR_STD_RX_QUEUES + nr_hairpin_queues,
								DP_NR_STD_TX_QUEUES + nr_hairpin_queues,
								&port_conf);
	if (DP_FAILED(ret)) {
		DPS_LOG_ERR("Cannot configure ethernet device", DP_LOG_PORT(port), DP_LOG_RET(ret));
		return DP_ERROR;
	}

	rxq_conf = dev_info->default_rxconf;
	rxq_conf.offloads = port_conf.rxmode.offloads;

	/* RX and TX queues config */
	for (int i = 0; i < DP_NR_STD_RX_QUEUES; ++i) {
		ret = rte_eth_rx_queue_setup(port->port_id, i, 1024,
									 port->socket_id,
									 &rxq_conf,
									 dp_layer->rte_mempool);
		if (DP_FAILED(ret)) {
			DPS_LOG_ERR("Rx queue setup failed", DP_LOG_PORT(port), DP_LOG_RET(ret));
			return DP_ERROR;
		}
	}

	txq_conf = dev_info->default_txconf;
	txq_conf.offloads = port_conf.txmode.offloads;

	for (int i = 0; i < DP_NR_STD_TX_QUEUES; ++i) {
		ret = rte_eth_tx_queue_setup(port->port_id, i, 2048,
									 port->socket_id,
									 &txq_conf);
		if (DP_FAILED(ret)) {
			DPS_LOG_ERR("Tx queue setup failed", DP_LOG_PORT(port), DP_LOG_RET(ret));
			return DP_ERROR;
		}
	}

	/* dp-service specific config */
	if (port_type == DP_PORT_VF) {
		DPS_LOG_INFO("INIT setting port to promiscuous mode", DP_LOG_PORT(port));
		ret = rte_eth_promiscuous_enable(port->port_id);
		if (DP_FAILED(ret)) {
			DPS_LOG_ERR("Promiscuous mode setting failed", DP_LOG_PORT(port), DP_LOG_RET(ret));
			return DP_ERROR;
		}
	}

	if (DP_FAILED(dp_load_mac(port))) {
		DPS_LOG_ERR("Cannot retrieve MAC address", DP_LOG_PORT(port));
		return DP_ERROR;
	}

	static_assert(sizeof(port->dev_name) == RTE_ETH_NAME_MAX_LEN, "Incompatible port dev_name size");
	rte_eth_dev_get_name_by_port(port->port_id, port->dev_name);

	if (port_type == DP_PORT_PF) {
		if (DP_FAILED(dp_get_pf_neigh_mac(dev_info->if_index, &pf_neigh_mac, &port->vm.info.own_mac)))
			return DP_ERROR;
		rte_ether_addr_copy(&pf_neigh_mac, &port->vm.info.neigh_mac);
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
	int socket_id;
	int ret;

	if (port_id >= RTE_DIM(_dp_port_table)) {
		DPS_LOG_ERR("Invalid port id", DP_LOG_PORTID(port_id), DP_LOG_MAX(RTE_DIM(_dp_port_table)));
		return NULL;
	}

	if (type == DP_PORT_PF) {
		if (dp_conf_get_nic_type() != DP_CONF_NIC_TYPE_TAP)
			if (DP_FAILED(dp_port_flow_isolate(port_id)))
				return NULL;
	}

	socket_id = rte_eth_dev_socket_id(port_id);
	if (DP_FAILED(socket_id)) {
		if (socket_id == SOCKET_ID_ANY) {
			DPS_LOG_WARNING("Cannot get numa socket", DP_LOG_PORTID(port_id));
		} else {
			DPS_LOG_ERR("Cannot get numa socket", DP_LOG_PORTID(port_id), DP_LOG_RET(rte_errno));
			return NULL;
		}
	}

	// oveflow check done by liming the number of calls to this function
	port = _dp_ports.end++;
	port->port_type = type;
	port->port_id = port_id;
	port->socket_id = socket_id;
	_dp_port_table[port_id] = port;

	if (DP_FAILED(dp_port_init_ethdev(port, dev_info, type)))
		return NULL;

	switch (type) {
	case DP_PORT_PF:
		if (DP_FAILED(dp_port_register_pf(port)))
			return NULL;
		ret = rte_eth_dev_callback_register(port_id, RTE_ETH_EVENT_INTR_LSC, dp_link_status_change_event_callback, NULL);
		if (DP_FAILED(ret)) {
			DPS_LOG_ERR("Cannot register link status callback", DP_LOG_RET(ret));
			return NULL;
		}
		break;
	case DP_PORT_VF:
		// All VFs belong to pf0, assign a tx queue from pf1 for it
		if (dp_conf_is_offload_enabled()) {
			port->peer_pf_port_id = dp_get_pf1()->port_id;
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

static int dp_port_set_up_hairpins(void)
{
	const struct dp_port *pf0 = dp_get_pf0();
	const struct dp_port *pf1 = dp_get_pf1();

	DP_FOREACH_PORT(&_dp_ports, port) {
		if (port->port_type == DP_PORT_PF) {
			port->peer_pf_port_id = (port->port_id == pf0->port_id ? pf1 : pf0)->port_id;
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
	char ifname[IF_NAMESIZE] = {0};
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
	char ifname[IF_NAMESIZE] = {0};
	int vf_count = 0;
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

int dp_ports_init(void)
{
	int num_of_vfs = get_dpdk_layer()->num_of_vfs;
	int num_of_ports = DP_MAX_PF_PORTS + num_of_vfs;

	_dp_ports.ports = (struct dp_port *)calloc(num_of_ports, sizeof(struct dp_port));
	if (!_dp_ports.ports) {
		DPS_LOG_ERR("Cannot allocate port table");
		return DP_ERROR;
	}
	_dp_ports.end = _dp_ports.ports;

	// these need to be done in order
	if (DP_FAILED(dp_port_init_pf(dp_conf_get_pf0_name()))
		|| DP_FAILED(dp_port_init_pf(dp_conf_get_pf1_name()))
		|| DP_FAILED(dp_port_init_vfs(dp_conf_get_vf_pattern(), num_of_vfs)))
		return DP_ERROR;

	if (dp_conf_is_offload_enabled()) {
		if (DP_FAILED(dp_port_set_up_hairpins()))
			return DP_ERROR;
	}

	return DP_OK;
}

static int dp_stop_eth_port(uint16_t port_id)
{
	int ret, ret2;

	// error already logged
	ret = rx_node_set_enabled(port_id, false);

	ret2 = rte_eth_dev_stop(port_id);
	if (DP_FAILED(ret2)) {
		DPS_LOG_ERR("Cannot stop ethernet port", DP_LOG_PORTID(port_id), DP_LOG_RET(ret2));
		ret = ret2;
	}

	return ret;
}

void dp_ports_free(void)
{
	// without stopping started ports, DPDK complains
	DP_FOREACH_PORT(&_dp_ports, port) {
		if (port->allocated)
			 dp_stop_eth_port(port->port_id);
	}
	free(_dp_ports.ports);
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

static int dp_port_bind_port_hairpins(const struct dp_port *port)
{
	// two pf port's hairpins are bound when processing the second port
	if (port == dp_get_pf0())
		return DP_OK;

	if (DP_FAILED(dp_hairpin_bind(port)))
		return DP_ERROR;

	return DP_OK;
}

static int dp_install_vf_init_rte_rules(struct dp_port *port)
{
	int ret;

	ret = dp_install_jump_rule_in_default_group(port, DP_RTE_FLOW_VNET_GROUP);
	if (DP_FAILED(ret)) {
		DPS_LOG_ERR("Cannot install default jump rule", DP_LOG_PORT(port), DP_LOG_RET(ret));
		return DP_ERROR;
	}

	return DP_OK;
}

static int dp_init_port(struct dp_port *port)
{
	if (DP_FAILED(rx_node_set_enabled(port->port_id, true)))
		return DP_ERROR;

	// TAP devices do not support offloading/isolation
	if (dp_conf_get_nic_type() == DP_CONF_NIC_TYPE_TAP)
		return DP_OK;

	if (port->port_type == DP_PORT_PF)
		if (DP_FAILED(dp_port_install_isolated_mode(port->port_id)))
			return DP_ERROR;

	if (dp_conf_is_offload_enabled()) {
#ifdef ENABLE_PYTEST
		if (port->peer_pf_port_id != dp_get_pf1()->port_id)
#endif
		if (DP_FAILED(dp_port_bind_port_hairpins(port)))
			return DP_ERROR;

		if (port->port_type == DP_PORT_VF)
			if (DP_FAILED(dp_install_vf_init_rte_rules(port)))
				assert(false);  // if any flow rule failed, stop process running due to possible hw/driver failure
	}

	return DP_OK;
}

int dp_start_port(struct dp_port *port)
{
	int ret;

	ret = rte_eth_dev_start(port->port_id);
	if (DP_FAILED(ret)) {
		DPS_LOG_ERR("Cannot start ethernet port", DP_LOG_PORT(port), DP_LOG_RET(ret));
		return ret;
	}

	ret = dp_init_port(port);
	if (DP_FAILED(ret)) {
		dp_stop_eth_port(port->port_id);
		return ret;
	}

	port->link_status = RTE_ETH_LINK_UP;
	port->allocated = true;
	return DP_OK;
}

int dp_stop_port(struct dp_port *port)
{
	if (DP_FAILED(dp_destroy_default_flow(port)))
		return DP_ERROR;

	if (DP_FAILED(dp_stop_eth_port(port->port_id)))
		return DP_ERROR;

	port->allocated = false;
	return DP_OK;
}
