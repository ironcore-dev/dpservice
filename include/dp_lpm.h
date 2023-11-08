#ifndef __INCLUDE_DP_LPM_PRIV_H__
#define __INCLUDE_DP_LPM_PRIV_H__

#include <rte_rib.h>
#include <rte_rib6.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_flow.h>
#include "dpdk_layer.h"
#include "dp_mbuf_dyn.h"
#include "dp_util.h"
#include "dp_firewall.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DP_IP_PROTO_UDP		0x11
#define DP_IP_PROTO_TCP		0x06
#define DP_IP_PROTO_ICMP	0x01
#define DP_IP_PROTO_SIPSR   0x2b
#define DP_IP_PROTO_IPv4_ENCAP 0x04
#define DP_IP_PROTO_IPv6_ENCAP 0x29

#define IP6_HDR_ROUTING_TYPE_SEGMENT_ROUTING 0x04

#define DP_IP6_HOP_LIMIT	0x40
#define DP_IP6_VTC_FLOW		0x60000000

#define IPV4_DP_RIB_MAX_RULES	1024
#define IPV6_DP_RIB_MAX_RULES	1024

#define DP_LPM_ROLLBACK	true
#define DP_LPM_DHCP_IP_DEPTH	32
#define DP_LPM_DHCP_IP6_DEPTH	128

#define DP_LIST_EXT_ROUTES true
#define DP_LIST_INT_ROUTES false

struct macip_entry {
	struct rte_ether_addr	own_mac;
	struct rte_ether_addr	neigh_mac;
	uint32_t	own_ip;
	uint32_t	neigh_ip;
	uint8_t		depth;
	uint8_t		dhcp_ipv6[16];
	uint8_t		vm_ipv6[16];
	uint32_t	pxe_ip;
	char		pxe_str[VM_MACHINE_PXE_MAX_LEN];
};

struct vm_entry {
	struct dp_fwall_head	fwall_head;
	struct macip_entry		info;
	uint32_t				vni;
	char					machineid[VM_IFACE_ID_MAX_LEN];
	uint8_t					ul_ipv6[16];
	bool					ready;
};

struct vm_route {
	int		vni;
	uint8_t	nh_ipv6[16];
};

// forward declaraction because 'struct vm_entry' is a part of 'struct dp_port'
struct dp_port;

struct dp_port *dp_get_ip4_dst_port(const struct dp_port *port,
									int t_vni,
									const struct dp_flow *df,
									struct vm_route *route,
									uint32_t *route_key);

struct dp_port *dp_get_ip6_dst_port(const struct dp_port *port,
									int t_vni,
									const struct rte_ipv6_hdr *ipv6_hdr,
									struct vm_route *route);

int dp_lpm_init(int socket_id);
void dp_lpm_free(void);

int dp_map_vm_handle(const char key[VM_IFACE_ID_MAX_LEN], struct dp_port *port);
void dp_unmap_vm_handle(const void *key);
struct dp_port *dp_get_port_with_vm_handle(const void *key);

uint32_t dp_get_gw_ip4(void);
const uint8_t *dp_get_gw_ip6(void);
const uint8_t *dp_get_port_ul_ip6(uint16_t port_id);

int dp_load_mac(struct dp_port *port);

bool dp_arp_cycle_needed(struct dp_port *port);

int dp_setup_vm(struct dp_port *port, int vni);
void dp_del_vm(struct dp_port *port);

int dp_add_route(struct dp_port *port, uint32_t vni, uint32_t t_vni, uint32_t ip,
				 const uint8_t *ip6, uint8_t depth);
int dp_del_route(struct dp_port *port, uint32_t vni, uint32_t ip, uint8_t depth);
int dp_add_route6(struct dp_port *port, uint32_t vni, uint32_t t_vni, const uint8_t *ipv6,
				  const uint8_t *ext_ip6, uint8_t depth);
int dp_del_route6(struct dp_port *port, uint32_t vni, const uint8_t *ipv6, uint8_t depth);
int dp_list_routes(struct dp_port *port, int vni, bool ext_routes, struct dp_grpc_responder *responder);

int dp_lpm_reset_all_route_tables(int socket_id);
int dp_lpm_reset_route_tables(int vni, int socket_id);

void dp_fill_ether_hdr(struct rte_ether_hdr *ether_hdr, uint16_t port_id, uint16_t ether_type);

#ifdef __cplusplus
}
#endif
#endif
