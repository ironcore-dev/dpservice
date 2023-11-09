#include "dp_vm.h"
#include "dp_vni.h"

static struct rte_hash *vm_handle_tbl = NULL;

int dp_vms_init(int socket_id)
{
	vm_handle_tbl = dp_create_jhash_table(DP_MAX_PORTS, VM_IFACE_ID_MAX_LEN,
										  "vm_handle_table", socket_id);
	if (!vm_handle_tbl)
		return DP_ERROR;

	return DP_OK;
}

void dp_vms_free(void)
{
	dp_free_jhash_table(vm_handle_tbl);
}

int dp_map_vm_handle(const char key[VM_IFACE_ID_MAX_LEN], struct dp_port *port)
{
	hash_sig_t hash = rte_hash_hash(vm_handle_tbl, key);
	int ret;

	ret = rte_hash_lookup_with_hash(vm_handle_tbl, key, hash);
	if (ret != -ENOENT) {
		if (DP_FAILED(ret))
			DPS_LOG_ERR("VM handle lookup failed", DP_LOG_RET(ret));
		else
			DPS_LOG_ERR("VM handle already exists");
		return DP_ERROR;
	}

	ret = rte_hash_add_key_with_hash_data(vm_handle_tbl, key, hash, port);
	if (DP_FAILED(ret)) {
		DPS_LOG_ERR("Cannot add VM handle data", DP_LOG_PORT(port), DP_LOG_RET(ret));
		return DP_ERROR;
	}

	static_assert(sizeof(port->vm.machineid) == VM_IFACE_ID_MAX_LEN, "Incompatible VM ID size");
	rte_memcpy(port->vm.machineid, key, VM_IFACE_ID_MAX_LEN);

	return DP_OK;
}

void dp_unmap_vm_handle(const void *key)
{
	rte_hash_del_key(vm_handle_tbl, key);
}

struct dp_port *dp_get_port_with_vm_handle(const void *key)
{
	struct dp_port *port;
	int ret;

	ret = rte_hash_lookup_data(vm_handle_tbl, key, (void **)&port);
	if (DP_FAILED(ret)) {
		if (ret != -ENOENT)
			DPS_LOG_ERR("Failed to look the VM port-id up", DP_LOG_RET(ret));
		return NULL;
	}

	return port;
}


int dp_setup_vm(struct dp_port *port, int vni)
{
	if (DP_FAILED(dp_create_vni_route_tables(vni, port->socket_id)))
		return DP_ERROR;

	dp_init_firewall_rules(port);
	port->vm.vni = vni;
	port->vm.ready = 1;
	return DP_OK;
}

void dp_del_vm(struct dp_port *port)
{
	uint32_t vni = port->vm.vni;

	dp_del_route(port, vni, port->vm.info.own_ip, 32);
	dp_del_route6(port, vni, port->vm.info.dhcp_ipv6, 128);

	if (DP_FAILED(dp_delete_vni_route_tables(vni)))
		DPS_LOG_WARNING("Unable to delete route tables", DP_LOG_VNI(vni));

	dp_del_all_firewall_rules(port);

	memset(&port->vm, 0, sizeof(port->vm));
	// own mac address in the vm_entry needs to be refilled due to the above cleaning process
	dp_load_mac(port);
}
