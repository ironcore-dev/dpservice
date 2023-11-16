#ifndef __DP_PORT_H__
#define __DP_PORT_H__

#include <stdint.h>
#include <stdbool.h>
#include <net/if.h>
#include <rte_pci.h>
#include "dp_conf.h"
#include "dp_firewall.h"
#include "dp_internal_stats.h"
#include "dpdk_layer.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DP_IFACE_ID_MAX_LEN	64

struct dp_iface_cfg {
	uint32_t				own_ip;
	uint32_t				neigh_ip;
	uint8_t					ip_depth;
	uint8_t					dhcp_ipv6[16];
	uint8_t					own_ipv6[16];
	uint8_t					ip6_depth;
	uint32_t				pxe_ip;
	char					pxe_str[DP_IFACE_PXE_MAX_LEN];
};

struct dp_port_iface {
	struct dp_fwall_head	fwall_head;
	struct dp_iface_cfg		cfg;
	uint32_t				vni;
	char					id[DP_IFACE_ID_MAX_LEN];
	uint8_t					ul_ipv6[16];
	bool					ready;
};

struct dp_port {
	bool					is_pf;
	uint16_t				port_id;
	char					port_name[IF_NAMESIZE];
	int						socket_id;
	uint8_t					link_status;
	bool					allocated;
	char					vf_name[IF_NAMESIZE];
	char					dev_name[RTE_ETH_NAME_MAX_LEN];
	uint8_t					peer_pf_hairpin_tx_rx_queue_offset;
	uint16_t				peer_pf_port_id;
	struct rte_ether_addr	own_mac;
	struct rte_ether_addr	neigh_mac;
	struct dp_port_iface	iface;
	struct rte_flow			*default_jump_flow;
	struct rte_flow			*default_capture_flow;
	bool					captured;
	struct dp_port_stats	stats;
};

struct dp_ports {
	struct dp_port *ports;
	struct dp_port *end;
};

// hidden structures for inline functions to access
extern struct dp_port *_dp_port_table[DP_MAX_PORTS];
extern struct dp_port *_dp_pf_ports[DP_MAX_PF_PORTS];
extern struct dp_ports _dp_ports;


struct dp_port *dp_get_port_by_name(const char *pci_name);

int dp_ports_init(void);
void dp_ports_free(void);

int dp_start_port(struct dp_port *port);
int dp_stop_port(struct dp_port *port);


static __rte_always_inline
int dp_load_mac(struct dp_port *port)
{
	return rte_eth_macaddr_get(port->port_id, &port->own_mac);
}

static __rte_always_inline
const uint8_t *dp_get_port_ul_ipv6(const struct dp_port *port)
{
	return port->iface.ready ? port->iface.ul_ipv6 : dp_conf_get_underlay_ip();
}

static __rte_always_inline
struct dp_port *dp_get_in_port(struct rte_mbuf *m)
{
	// m->port should've already been validated
	return _dp_port_table[m->port];
}

static __rte_always_inline
struct dp_port *dp_get_out_port(struct dp_flow *df)
{
	// df->nxt_hop should've already been validated
	return _dp_port_table[df->nxt_hop];
}

static __rte_always_inline
struct dp_port *dp_get_port_by_id(uint16_t port_id)
{
	if (unlikely(port_id >= RTE_DIM(_dp_port_table))) {
		DPS_LOG_ERR("Port not registered in dpservice", DP_LOG_PORTID(port_id));
		return NULL;
	}
	return _dp_port_table[port_id];
}

static __rte_always_inline
const struct dp_ports *dp_get_ports(void)
{
	return &_dp_ports;
}

#define DP_FOREACH_PORT(DP_PORTS, VARNAME) \
	for (struct dp_port *VARNAME = (DP_PORTS)->ports; \
		 VARNAME < (DP_PORTS)->end; \
		 ++VARNAME)

static __rte_always_inline
const struct dp_port *dp_get_pf0(void)
{
	return _dp_pf_ports[0];
}

static __rte_always_inline
const struct dp_port *dp_get_pf1(void)
{
	return _dp_pf_ports[1];
}

static __rte_always_inline
struct dp_port *dp_get_port_by_pf_index(uint16_t index)
{
	return index < RTE_DIM(_dp_pf_ports) ? _dp_pf_ports[index] : NULL;
}

#ifdef __cplusplus
}
#endif

#endif
