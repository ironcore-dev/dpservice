// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#include "dp_iface.h"
#include "dp_vni.h"

static struct rte_hash *iface_id_table = NULL;

int dp_ifaces_init(int socket_id)
{
	iface_id_table = dp_create_jhash_table(DP_MAX_PORTS, DP_IFACE_ID_MAX_LEN,
										   "iface_id_table", socket_id);
	if (!iface_id_table)
		return DP_ERROR;

	return DP_OK;
}

void dp_ifaces_free(void)
{
	dp_free_jhash_table(iface_id_table);
}

int dp_map_iface_id(const char iface_id[DP_IFACE_ID_MAX_LEN], struct dp_port *port)
{
	hash_sig_t hash = rte_hash_hash(iface_id_table, iface_id);
	int ret;

	ret = rte_hash_lookup_with_hash(iface_id_table, iface_id, hash);
	if (ret != -ENOENT) {
		if (DP_FAILED(ret))
			DPS_LOG_ERR("VM handle lookup failed", DP_LOG_RET(ret));
		else
			DPS_LOG_ERR("VM handle already exists");
		return DP_ERROR;
	}

	ret = rte_hash_add_key_with_hash_data(iface_id_table, iface_id, hash, port);
	if (DP_FAILED(ret)) {
		DPS_LOG_ERR("Cannot add VM handle data", DP_LOG_PORT(port), DP_LOG_RET(ret));
		return DP_ERROR;
	}

	static_assert(sizeof(port->iface.id) == DP_IFACE_ID_MAX_LEN, "Incompatible interface ID size");
	rte_memcpy(port->iface.id, iface_id, DP_IFACE_ID_MAX_LEN);

	return DP_OK;
}

void dp_unmap_iface_id(const char iface_id[DP_IFACE_ID_MAX_LEN])
{
	rte_hash_del_key(iface_id_table, iface_id);
}

struct dp_port *dp_get_port_with_iface_id(const char iface_id[DP_IFACE_ID_MAX_LEN])
{
	struct dp_port *port;
	int ret;

	ret = rte_hash_lookup_data(iface_id_table, iface_id, (void **)&port);
	if (DP_FAILED(ret)) {
		if (ret != -ENOENT)
			DPS_LOG_ERR("Failed to look the VM port-id up", DP_LOG_RET(ret));
		return NULL;
	}

	return port;
}


int dp_setup_iface(struct dp_port *port, uint32_t vni)
{
	if (DP_FAILED(dp_create_vni_route_tables(vni, port->socket_id)))
		return DP_ERROR;

	dp_init_firewall_rules(port);
	port->iface.vni = vni;
	port->iface.ready = 1;
	return DP_OK;
}

void dp_delete_iface(struct dp_port *port)
{
	uint32_t vni = port->iface.vni;

	dp_del_route(port, vni, port->iface.cfg.own_ip, 32);
	dp_del_route6(port, vni, port->iface.cfg.dhcp_ipv6, 128);

	if (DP_FAILED(dp_delete_vni_route_tables(vni)))
		DPS_LOG_WARNING("Unable to delete route tables", DP_LOG_VNI(vni));

	dp_del_all_firewall_rules(port);

	memset(&port->iface, 0, sizeof(port->iface));
	// own mac address needs to be refilled due to the above cleaning process
	dp_load_mac(port);
}
