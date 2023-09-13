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
	uint8_t		pxe_str[VM_MACHINE_PXE_MAX_LEN];
};

struct vm_entry {
	struct dp_fwall_head	fwall_head;
	struct macip_entry		info;
	uint32_t				vni;
	uint8_t					machineid[VM_IFACE_ID_MAX_LEN];
	uint8_t					ul_ipv6[16];
	uint8_t					vm_ready;
};

struct vm_route {
	int		vni;
	uint8_t	nh_ipv6[16];

};

int dp_setup_vm(int port_id, int vni, int socketid);
int dp_setup_vm6(int port_id, int vni, int socketid);
int dp_lookup_ip4_route(int port_id, int t_vni, const struct dp_flow *df, int socketid,
						struct vm_route *r, uint32_t *route_key, uint64_t *dst_port_id);
int dp_get_ip6_dst_port(int port_id, int t_vni, const struct rte_ipv6_hdr *ipv6_hdr,
						struct vm_route *r, int socketid);

int dp_lpm_init(int socket_id);
void dp_lpm_free(void);
int dp_map_vm_handle(void *key, uint16_t portid);
int dp_get_portid_with_vm_handle(void *key);
void dp_del_portid_with_vm_handle(void *key);

uint32_t dp_get_gw_ip4(void);
const uint8_t *dp_get_gw_ip6(void);
uint32_t dp_get_dhcp_range_ip4(uint16_t portid);
uint8_t *dp_get_dhcp_range_ip6(uint16_t portid);
uint8_t *dp_get_vm_ip6(uint16_t portid);
uint8_t *dp_get_vm_ul_ip6(uint16_t portid);
const uint8_t *dp_get_port_ul_ip6(uint16_t portid);
int dp_add_route(uint16_t portid, uint32_t vni, uint32_t t_vni, uint32_t ip,
				 uint8_t *ip6, uint8_t depth, int socketid);
int dp_del_route(uint16_t portid, uint32_t vni, uint32_t ip, uint8_t depth, int socketid);
int dp_add_route6(uint16_t portid, uint32_t vni, uint32_t t_vni, uint8_t *ipv6,
				  uint8_t *ext_ip6, uint8_t depth, int socketid);
int dp_del_route6(uint16_t portid, uint32_t vni, uint8_t *ipv6, uint8_t depth, int socketid);
int dp_list_routes(int vni, int socketid, uint16_t portid, bool ext_routes, struct dp_grpc_responder *responder);
void dp_set_dhcp_range_ip4(uint16_t portid, uint32_t ip, uint8_t depth);
void dp_set_dhcp_range_ip6(uint16_t portid, uint8_t *ipv6, uint8_t depth);
void dp_set_vm_ip6(uint16_t portid, uint8_t *ipv6);
void dp_set_vm_ul_ip6(uint16_t portid, uint8_t *ipv6);
void dp_set_mac(uint16_t portid);
struct rte_ether_addr *dp_get_mac(uint16_t portid);
void dp_set_neigh_mac(uint16_t portid, struct rte_ether_addr *neigh);
struct rte_ether_addr *dp_get_neigh_mac(uint16_t portid);
bool dp_arp_cycle_needed(uint16_t portid);
void dp_del_vm(int portid, int socketid);
int dp_get_active_vm_ports(int *act_ports);
uint8_t *dp_get_vm_machineid(uint16_t portid);
uint32_t dp_get_vm_vni(uint16_t portid);
uint32_t dp_get_vm_pxe_ip4(uint16_t portid);
void dp_set_vm_pxe_ip4(uint16_t portid, uint32_t ip);
char *dp_get_vm_pxe_str(uint16_t portid);
void dp_set_vm_pxe_str(uint16_t portid, char *p_str);
int dp_lpm_reset_all_route_tables(int socketid);
int dp_lpm_reset_route_tables(int vni, int socketid);
struct dp_fwall_head *dp_get_fwall_head(int port_id);
void dp_set_fwall_head(int port_id, struct dp_fwall_head *fwall_head);
#ifdef __cplusplus
}
#endif
#endif
