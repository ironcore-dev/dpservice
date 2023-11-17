#ifndef __INCLUDE_DP_IFACE_H__
#define __INCLUDE_DP_IFACE_H__

#include "dp_port.h"

#ifdef __cplusplus
extern "C" {
#endif

int dp_ifaces_init(int socket_id);
void dp_ifaces_free(void);

int dp_map_iface_id(const char iface_id[DP_IFACE_ID_MAX_LEN], struct dp_port *port);
void dp_unmap_iface_id(const char iface_id[DP_IFACE_ID_MAX_LEN]);
struct dp_port *dp_get_port_with_iface_id(const char iface_id[DP_IFACE_ID_MAX_LEN]);

int dp_setup_iface(struct dp_port *port, int vni);
void dp_delete_iface(struct dp_port *port);


static __rte_always_inline
bool dp_arp_cycle_needed(const struct dp_port *port)
{
	static struct rte_ether_addr nul_mac = {0};

	return port->iface.ready
		&& rte_is_same_ether_addr(&port->neigh_mac, &nul_mac);
}

static __rte_always_inline
void dp_fill_ether_hdr(struct rte_ether_hdr *ether_hdr, const struct dp_port *port, uint16_t ether_type)
{
	rte_ether_addr_copy(&port->neigh_mac, &ether_hdr->dst_addr);
	rte_ether_addr_copy(&port->own_mac, &ether_hdr->src_addr);
	ether_hdr->ether_type = htons(ether_type);
}

#ifdef __cplusplus
}
#endif

#endif
