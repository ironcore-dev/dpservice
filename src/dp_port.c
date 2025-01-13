// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#include "dp_port.h"
#include <rte_bus_pci.h>
#include "dp_conf.h"
#include "dp_error.h"
#include "dp_hairpin.h"
#include "dp_log.h"
#include "dp_lpm.h"
#include "dp_netlink.h"
#ifdef ENABLE_VIRTSVC
#	include "dp_virtsvc.h"
#endif
#include "monitoring/dp_event.h"
#include "monitoring/dp_graphtrace.h"
#include "nodes/rx_node.h"
#include "rte_flow/dp_rte_async_flow.h"
#include "rte_flow/dp_rte_async_flow_isolation.h"
#include "rte_flow/dp_rte_async_flow_template.h"
#include "rte_flow/dp_rte_flow.h"
#include "rte_flow/dp_rte_flow_capture.h"
#include "rte_flow/dp_rte_flow_init.h"

#define DP_PORT_INIT_PF true
#define DP_PORT_INIT_VF false

#define DP_PORT_NEIGHMAC_INITIAL_PERIOD 1
#define DP_PORT_NEIGHMAC_BACKOFF_COEF 2
#define DP_PORT_NEIGHMAC_MAX_PERIOD 60

#define DP_METER_CIR_BASE_VALUE  (1024 * 1024) // 1 Mbits
#define DP_METER_EBS_BREAK_VALUE 100     // 100 Mbits/s, it used to differentiate different ebs calculation strategy to achieve relative stable metering results. epirical value.
#define DP_METER_MBITS_TO_BYTES  (1024 * 1024 / 8)

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
	.intr_conf = {
		.lsc = 1, /**< lsc interrupt feature enabled */
	},
};

static const struct rte_meter_srtcm_params dp_srtcm_params_base = {
	.cir = DP_METER_CIR_BASE_VALUE * 100 / 8,	// 100 Mbits/s
	.cbs = 4096,			// 4 KBytes
	.ebs = DP_METER_EBS_BREAK_VALUE * DP_METER_MBITS_TO_BYTES,			// DP_METER_EBS_BREAK_VALUE -> kbps -> * 1000 -> bytes
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

static int dp_port_init_ethdev(struct dp_port *port, struct rte_eth_dev_info *dev_info)
{
	struct dp_dpdk_layer *dp_layer = get_dpdk_layer();
	struct rte_eth_txconf txq_conf;
	struct rte_eth_rxconf rxq_conf;
	struct rte_eth_conf port_conf = port_conf_default;
	uint16_t nr_hairpin_queues;
	int ret;

	/* Default config */
	port_conf.txmode.offloads &= dev_info->tx_offload_capa;

	if (dp_conf_get_nic_type() == DP_CONF_NIC_TYPE_TAP || dp_conf_is_multiport_eswitch())
		nr_hairpin_queues = 0;
	else
		nr_hairpin_queues = port->is_pf
			? (uint16_t)(DP_NR_PF_HAIRPIN_RX_TX_QUEUES + DP_NR_VF_HAIRPIN_RX_TX_QUEUES * dp_layer->num_of_vfs)
			: DP_NR_VF_HAIRPIN_RX_TX_QUEUES;

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
	for (uint16_t i = 0; i < DP_NR_STD_RX_QUEUES; ++i) {
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

	for (uint16_t i = 0; i < DP_NR_STD_TX_QUEUES; ++i) {
		ret = rte_eth_tx_queue_setup(port->port_id, i, 2048,
									 port->socket_id,
									 &txq_conf);
		if (DP_FAILED(ret)) {
			DPS_LOG_ERR("Tx queue setup failed", DP_LOG_PORT(port), DP_LOG_RET(ret));
			return DP_ERROR;
		}
	}

	/* dp-service specific config */
	if (!port->is_pf) {
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

	if (dp_conf_is_multiport_eswitch() && DP_FAILED(dp_configure_async_flows(port->port_id)))
		return DP_ERROR;

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

static int dp_get_port_socket_id(uint16_t port_id)
{
	int socket_id;

	if (port_id >= RTE_DIM(_dp_port_table)) {
		DPS_LOG_ERR("Invalid port id", DP_LOG_PORTID(port_id), DP_LOG_MAX(RTE_DIM(_dp_port_table)));
		return DP_ERROR;
	}

	socket_id = rte_eth_dev_socket_id(port_id);
	if (DP_FAILED(socket_id)) {
		if (socket_id == SOCKET_ID_ANY) {
			DPS_LOG_WARNING("Cannot get numa socket, using 'any'", DP_LOG_PORTID(port_id));
		} else {
			DPS_LOG_ERR("Cannot get numa socket", DP_LOG_PORTID(port_id), DP_LOG_RET(rte_errno));
			return DP_ERROR;
		}
	}

	return socket_id;
}

static struct dp_port *dp_port_init_interface(uint16_t port_id, struct rte_eth_dev_info *dev_info, bool is_pf)
{
	static int last_pf1_hairpin_tx_rx_queue_offset = 1;
	struct dp_port *port;
	int socket_id;
	int ret;

	socket_id = dp_get_port_socket_id(port_id);
	if (DP_FAILED(socket_id) && socket_id != SOCKET_ID_ANY)
		return NULL;

	if (is_pf && dp_conf_get_nic_type() != DP_CONF_NIC_TYPE_TAP)
		if (DP_FAILED(dp_port_flow_isolate(port_id)))
			return NULL;

	// oveflow check done by liming the number of calls to this function
	port = _dp_ports.end++;
	port->is_pf = is_pf;
	port->port_id = port_id;
	port->socket_id = socket_id;
	port->if_index = dev_info->if_index;
	_dp_port_table[port_id] = port;

	if (is_pf && DP_FAILED(dp_port_register_pf(port)))
		return NULL;

	if (DP_FAILED(dp_port_init_ethdev(port, dev_info)))
		return NULL;

	if (is_pf) {
		ret = rte_eth_dev_callback_register(port_id, RTE_ETH_EVENT_INTR_LSC, dp_link_status_change_event_callback, NULL);
		if (DP_FAILED(ret)) {
			DPS_LOG_ERR("Cannot register link status callback", DP_LOG_RET(ret));
			return NULL;
		}
		rte_timer_init(&port->neighmac_timer);
	} else {
		// All VFs belong to pf0, assign a tx queue from pf1 for it
		if (dp_conf_is_offload_enabled()) {
			port->peer_pf_port_id = dp_get_pf1()->port_id;
			port->peer_pf_hairpin_tx_rx_queue_offset = (uint8_t)last_pf1_hairpin_tx_rx_queue_offset++;
			if (last_pf1_hairpin_tx_rx_queue_offset > UINT8_MAX) {
				DPS_LOG_ERR("Too many VFs, cannot create more hairpins");
				return NULL;
			}
		}
		// No link status callback, VFs are not critical for cross-hypervisor communication
	}

	return port;
}

static int dp_port_set_up_hairpins(void)
{
	const struct dp_port *pf0 = dp_get_pf0();
	const struct dp_port *pf1 = dp_get_pf1();

	DP_FOREACH_PORT(&_dp_ports, port) {
		if (port->is_pf) {
			port->peer_pf_port_id = (port->port_id == pf0->port_id ? pf1 : pf0)->port_id;
			port->peer_pf_hairpin_tx_rx_queue_offset = 1;
		}
		if (DP_FAILED(dp_hairpin_setup(port)))
				return DP_ERROR;
	}
	return DP_OK;
}

static int dp_find_port(const char *iface_name, uint16_t *out_port_id, struct rte_eth_dev_info *out_dev_info)
{
	uint16_t port_id;
	char ifname[IF_NAMESIZE] = {0};

	RTE_ETH_FOREACH_DEV(port_id) {
		if (DP_FAILED(dp_get_dev_info(port_id, out_dev_info, ifname)))
			return DP_ERROR;
		if (!strncmp(iface_name, ifname, sizeof(ifname))) {
			*out_port_id = port_id;
			return DP_OK;
		}
	}
	DPS_LOG_ERR("No such interface", DP_LOG_NAME(iface_name));
	return DP_ERROR;
}

static int dp_port_init_pf(const char *pf_name)
{
	uint16_t port_id;
	struct rte_eth_dev_info dev_info;
	struct dp_port *port;

	if (DP_FAILED(dp_find_port(pf_name, &port_id, &dev_info)))
		return DP_ERROR;

	DPS_LOG_INFO("INIT initializing PF port", DP_LOG_PORTID(port_id), DP_LOG_IFNAME(pf_name));
	port = dp_port_init_interface(port_id, &dev_info, DP_PORT_INIT_PF);
	if (!port)
		return DP_ERROR;

	snprintf(port->port_name, sizeof(port->port_name), "%s", pf_name);
	return DP_OK;
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
			port = dp_port_init_interface(port_id, &dev_info, DP_PORT_INIT_VF);
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

static void dp_destroy_default_async_templates(struct dp_port *port)
{
	for (uint8_t i = 0; i < RTE_DIM(port->default_async_rules.default_templates); ++i)
		dp_destroy_async_template(port->port_id, port->default_async_rules.default_templates[i]);
}

static int dp_stop_eth_port(struct dp_port *port)
{
	int ret;

	DPS_LOG_INFO("Stopping port", DP_LOG_PORT(port));

	if (dp_conf_is_multiport_eswitch()) {
#ifdef ENABLE_VIRTSVC
		if (port->is_pf)
			dp_destroy_virtsvc_async_isolation_rules(port->port_id);
#endif
		dp_destroy_async_rules(port->port_id,
							   port->default_async_rules.default_flows,
							   RTE_DIM(port->default_async_rules.default_flows));
		dp_destroy_default_async_templates(port);
	}

	ret = rte_eth_dev_stop(port->port_id);
	if (DP_FAILED(ret))
		DPS_LOG_ERR("Cannot stop ethernet port", DP_LOG_PORT(port), DP_LOG_RET(ret));

	return ret;
}

void dp_ports_stop(void)
{
	// in multiport-mode, PF0 needs to be stopped last
	struct dp_port *pf0 = dp_get_port_by_pf_index(0);

	// without stopping started ports, DPDK complains
	DP_FOREACH_PORT(&_dp_ports, port) {
		if (port->allocated && port != pf0)
			dp_stop_eth_port(port);
	}
	if (pf0 && pf0->allocated)
		dp_stop_eth_port(pf0);
}

void dp_ports_free(void)
{
	free(_dp_ports.ports);
}


static int dp_port_install_sync_isolated_mode(uint16_t port_id)
{
	DPS_LOG_INFO("Init isolation flow rules");
	if (DP_FAILED(dp_install_isolated_mode_ipip(port_id, IPPROTO_IPIP))
		|| DP_FAILED(dp_install_isolated_mode_ipip(port_id, IPPROTO_IPV6)))
		return DP_ERROR;
#ifdef ENABLE_VIRTSVC
	return dp_install_virtsvc_sync_isolation_rules(port_id);
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

static int dp_port_install_async_isolated_mode(struct dp_port *port)
{
	DPS_LOG_INFO("Init async isolation flow rules");
	if (DP_FAILED(dp_create_pf_async_isolation_rules(port)))
		return DP_ERROR;
	return DP_OK;
}

static int dp_port_create_default_pf_async_templates(struct dp_port *port)
{
	DPS_LOG_INFO("Installing PF async templates", DP_LOG_PORT(port));
	if (DP_FAILED(dp_create_pf_async_isolation_templates(port))) {
		DPS_LOG_ERR("Failed to create pf async isolation templates", DP_LOG_PORT(port));
		return DP_ERROR;
	}
#ifdef ENABLE_VIRTSVC
	if (DP_FAILED(dp_create_virtsvc_async_isolation_templates(port, IPPROTO_TCP))
		|| DP_FAILED(dp_create_virtsvc_async_isolation_templates(port, IPPROTO_UDP))
	) {
		DPS_LOG_ERR("Failed to create virtsvc async isolation templates", DP_LOG_PORT(port));
		return DP_ERROR;
	}
#endif
	return DP_OK;
}


static void dp_acquire_neigh_mac(struct dp_port *port);

static void dp_neighmac_timer_cb(__rte_unused struct rte_timer *timer, void *arg)
{
	struct dp_port *port = arg;

	port->neighmac_period *= DP_PORT_NEIGHMAC_BACKOFF_COEF;
	if (port->neighmac_period > DP_PORT_NEIGHMAC_MAX_PERIOD)
		port->neighmac_period = DP_PORT_NEIGHMAC_MAX_PERIOD;

	dp_acquire_neigh_mac(port);
}

static void dp_acquire_neigh_mac(struct dp_port *port)
{
	struct rte_ether_addr pf_neigh_mac = {0};
	int ret;

	if (DP_FAILED(dp_get_pf_neigh_mac(port->if_index, &pf_neigh_mac, &port->own_mac))) {
		DPS_LOG_WARNING("No neighboring router, setting timer", DP_LOG_VALUE(port->neighmac_period), DP_LOG_PORT(port));

		// need to use the same lcore each time, thus staying on main one even when called from the worker
		ret = rte_timer_reset(&port->neighmac_timer, port->neighmac_period * rte_get_timer_hz(),
							  SINGLE, rte_get_main_lcore(), dp_neighmac_timer_cb, port);
		if (DP_FAILED(ret))
			DPS_LOG_WARNING("Cannot start neigboring router timer", DP_LOG_PORT(port), DP_LOG_RET(ret));

		return;
	}

	if (DP_FAILED(dp_send_event_neighmac_msg(port->port_id, &pf_neigh_mac)))
		DPS_LOG_WARNING("Cannot send neigboring router mac to worker thread");
}

void dp_start_acquiring_neigh_mac(struct dp_port *port)
{
	port->neighmac_period = DP_PORT_NEIGHMAC_INITIAL_PERIOD;
	dp_acquire_neigh_mac(port);
}

void dp_stop_acquiring_neigh_mac(struct dp_port *port)
{
	rte_timer_stop_sync(&port->neighmac_timer);
}

int dp_set_neigh_mac(uint16_t port_id, const struct rte_ether_addr *mac)
{
	struct dp_port *port;
	char strmac[18];

	port = dp_get_port_by_id(port_id);
	if (!port) {
		DPS_LOG_WARNING("Cannot set neighboring router, port invalid", DP_LOG_PORTID(port_id));
		return DP_ERROR;
	}

	rte_ether_addr_copy(mac, &port->neigh_mac);

	snprintf(strmac, sizeof(strmac), RTE_ETHER_ADDR_PRT_FMT, RTE_ETHER_ADDR_BYTES(&port->neigh_mac));
	DPS_LOG_INFO("Setting PF neighboring router", _DP_LOG_STR("mac", strmac), DP_LOG_PORT(port));
	return DP_OK;
}


static int dp_init_port(struct dp_port *port)
{
	// TAP devices do not support offloading/isolation
	if (dp_conf_get_nic_type() == DP_CONF_NIC_TYPE_TAP)
		return DP_OK;

	if (port->is_pf) {
		if (dp_conf_is_multiport_eswitch()) {
			if (DP_FAILED(dp_port_create_default_pf_async_templates(port))
				|| DP_FAILED(dp_port_install_async_isolated_mode(port)))
				return DP_ERROR;
		} else
			if (DP_FAILED(dp_port_install_sync_isolated_mode(port->port_id)))
				return DP_ERROR;
	}

	if (dp_conf_is_offload_enabled()) {
		if (DP_FAILED(dp_port_bind_port_hairpins(port)))
			return DP_ERROR;

		if (!port->is_pf)
			if (DP_FAILED(dp_install_vf_init_rte_rules(port)))
				assert(false);  // if any flow rule failed, stop process running due to possible hw/driver failure
	}

	return DP_OK;
}

int dp_start_port(struct dp_port *port)
{
	struct rte_eth_link link = {
		.link_status = RTE_ETH_LINK_DOWN
	};
	int ret;

	DPS_LOG_INFO("Starting port", DP_LOG_PORT(port));

	ret = rte_eth_dev_start(port->port_id);
	if (DP_FAILED(ret)) {
		DPS_LOG_ERR("Cannot start ethernet port", DP_LOG_PORT(port), DP_LOG_RET(ret));
		return ret;
	}

	ret = dp_init_port(port);
	if (DP_FAILED(ret)) {
		dp_stop_eth_port(port);
		return ret;
	}

	if (port->is_pf) {
		// this really only fails on bad arguments (or incompatible driver)
		ret = rte_eth_link_get(port->port_id, &link);
		if (DP_FAILED(ret))
			DPS_LOG_WARNING("Unable to get the initial link status, assuming it down", DP_LOG_PORT(port), DP_LOG_RET(ret));
	} else
		link.link_status = RTE_ETH_LINK_UP;

	port->link_status = link.link_status;
	port->allocated = true;
	return DP_OK;
}

int dp_start_pf_port(uint16_t index)
{
	struct dp_port *port = dp_get_port_by_pf_index(index);

	if (!port) {
		DPS_LOG_ERR("Invalid PF index", DP_LOG_VALUE(index), DP_LOG_MAX(DP_MAX_PF_PORTS));
		return DP_ERROR;
	}

	if (DP_FAILED(dp_start_port(port)))
		return DP_ERROR;

	DPS_LOG_INFO("Received initial PF link state", DP_LOG_LINKSTATE(port->link_status), DP_LOG_PORT(port));

	if (port->link_status == RTE_ETH_LINK_UP)
		dp_start_acquiring_neigh_mac(port);

	return DP_OK;
}

int dp_stop_port(struct dp_port *port)
{
	if (DP_FAILED(dp_destroy_default_flow(port)))
		return DP_ERROR;

	if (DP_FAILED(dp_stop_eth_port(port)))
		return DP_ERROR;

	port->allocated = false;
	return DP_OK;
}


static int dp_port_total_flow_meter_config(struct dp_port *port, uint64_t total_flow_rate_cap)
{
	return dp_set_vf_rate_limit(port->port_id, total_flow_rate_cap);
}

static int dp_port_public_flow_meter_config(struct dp_port *port, uint64_t public_flow_rate_cap)
{
	struct rte_meter_srtcm_params srtcm_params = dp_srtcm_params_base;
	int ret;

	if (!public_flow_rate_cap) {
		port->port_srtcm_profile = (struct rte_meter_srtcm_profile){0}; // reset the srtcm profile to 0 to erase any value inside it
		return DP_OK;
	}

	srtcm_params.cir = DP_METER_CIR_BASE_VALUE * (public_flow_rate_cap / 8); // Mbits/s -> bytes/s
	if (public_flow_rate_cap < DP_METER_EBS_BREAK_VALUE)
		srtcm_params.ebs = public_flow_rate_cap * DP_METER_MBITS_TO_BYTES;

	ret = rte_meter_srtcm_profile_config(&port->port_srtcm_profile, &srtcm_params);
	if (DP_FAILED(ret)) {
		DPS_LOG_ERR("Cannot configure meter profile", DP_LOG_PORT(port), DP_LOG_RET(ret));
		return DP_ERROR;
	}

	ret = rte_meter_srtcm_config(&port->port_srtcm, &port->port_srtcm_profile);
	if (DP_FAILED(ret)) {
		DPS_LOG_ERR("Cannot configure meter", DP_LOG_PORT(port), DP_LOG_RET(ret));
		port->port_srtcm_profile = (struct rte_meter_srtcm_profile){0}; // reset the srtcm profile to 0 to erase the above value assignment
		return DP_ERROR;
	}

	return DP_OK;
}

int dp_port_meter_config(struct dp_port *port, uint64_t total_flow_rate_cap, uint64_t public_flow_rate_cap)
{
	int err;

	if (dp_conf_get_nic_type() != DP_CONF_NIC_TYPE_MELLANOX) {
		if (public_flow_rate_cap != 0 || total_flow_rate_cap != 0)
			DPS_LOG_WARNING("Metering config will not take effect due to the NIC type",
							DP_LOG_PORT(port), DP_LOG_METER_TOTAL(total_flow_rate_cap), DP_LOG_METER_PUBLIC(public_flow_rate_cap));
		return DP_OK;
	}

	if (public_flow_rate_cap > total_flow_rate_cap) {
		DPS_LOG_ERR("Public flow rate cap cannot be greater than total flow rate cap",
					DP_LOG_PORT(port), DP_LOG_METER_TOTAL(total_flow_rate_cap), DP_LOG_METER_PUBLIC(public_flow_rate_cap));
		return DP_ERROR;
	}

	err = dp_port_total_flow_meter_config(port, total_flow_rate_cap);
	if (DP_FAILED(err)) {
		if (err == -ENOENT)
			DPS_LOG_WARNING("Cannot find sysfs path or file to regulate traffic rate, thus total flow rate metering is ignored", DP_LOG_PORT(port));
		else {
			DPS_LOG_ERR("Cannot set total flow meter", DP_LOG_PORT(port));
			return DP_ERROR;
		}
	} else {
		port->iface.total_flow_rate_cap = total_flow_rate_cap;
	}

	if (DP_FAILED(dp_port_public_flow_meter_config(port, public_flow_rate_cap))) {
		DPS_LOG_ERR("Cannot set public flow meter", DP_LOG_PORT(port));
		if (DP_FAILED(dp_port_total_flow_meter_config(port, 0))) {
			DPS_LOG_ERR("Cannot reset total flow meter", DP_LOG_PORT(port));
			return DP_ERROR;
		}
		port->iface.total_flow_rate_cap = 0;
		return DP_ERROR;
	}
	port->iface.public_flow_rate_cap = public_flow_rate_cap;

	return DP_OK;
}
