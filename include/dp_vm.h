#ifndef __DP_VM_H__
#define __DP_VM_H__

#include "dp_port.h"

#ifdef __cplusplus
extern "C" {
#endif

int dp_vms_init(int socket_id);
void dp_vms_free(void);

int dp_map_vm_handle(const char key[VM_IFACE_ID_MAX_LEN], struct dp_port *port);
void dp_unmap_vm_handle(const void *key);
struct dp_port *dp_get_port_with_vm_handle(const void *key);

int dp_setup_vm(struct dp_port *port, int vni);
void dp_del_vm(struct dp_port *port);


static __rte_always_inline
bool dp_arp_cycle_needed(const struct dp_port *port)
{
	static struct rte_ether_addr nul_mac = {0};

	return port->vm.ready
		&& rte_is_same_ether_addr(&port->vm.info.neigh_mac, &nul_mac);
}

static __rte_always_inline
void dp_fill_ether_hdr(struct rte_ether_hdr *ether_hdr, const struct dp_port *port, uint16_t ether_type)
{
	rte_ether_addr_copy(&port->vm.info.neigh_mac, &ether_hdr->dst_addr);
	rte_ether_addr_copy(&port->vm.info.own_mac, &ether_hdr->src_addr);
	ether_hdr->ether_type = htons(ether_type);
}

#ifdef __cplusplus
}
#endif

#endif
