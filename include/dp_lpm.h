#ifndef __INCLUDE_DP_LPM_PRIV_H__
#define __INCLUDE_DP_LPM_PRIV_H__

#include <rte_rib.h>
#include <rte_rib6.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_flow.h>
#include "dpdk_layer.h"
#include "node_api.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DP_ROUTE_DHCP		-2
#define DP_ROUTE_DROP		-3
#define DP_ROUTE_FIREWALL	-4
#define DP_ROUTE_NAT		-5

#define DP_IP_PROTO_UDP		0x11
#define DP_IP_PROTO_TCP		0x06
#define DP_IP_PROTO_ICMP	0x01
#define DP_IP6_HOP_LIMIT	0x40
#define DP_IP6_VTC_FLOW		0x60000000

#define IPV4_DP_RIB_MAX_RULES	1024
#define IPV6_DP_RIB_MAX_RULES	1024

#define DP_NAT_OFF	0
#define DP_NAT_ON	1
#define DP_NAT_SNAT	2
#define DP_NAT_DNAT	3

#define VM_MACHINE_ID_STR_LEN 64

struct macip_entry {
	struct rte_ether_addr	own_mac;
	struct rte_ether_addr	neigh_mac;
	uint32_t	own_ip;
	uint32_t	neigh_ip;
	uint32_t	virt_ip;
	uint8_t		depth;
	uint8_t		nat;
	uint8_t	dhcp_ipv6[16];
	uint8_t	vm_ipv6[16];
	uint8_t	virt_ipv6[16];
};

struct vm_entry {
	struct rte_rib		*ipv4_rib[DP_NB_SOCKETS];
	struct rte_rib6		*ipv6_rib[DP_NB_SOCKETS];
	struct macip_entry	info;
	int					vni;
	uint8_t				machineid[VM_MACHINE_ID_STR_LEN];
	uint8_t				vm_ready;
};

struct vm_route {
	int		vni;
	uint8_t	nh_ipv6[16];
};

void setup_lpm(int port_id, int vni, const int socketid);
void setup_lpm6(int port_id, int vni, const int socketid);
int lpm_get_ip4_dst_port(int port_id, int t_vni, const struct rte_ipv4_hdr *ipv4_hdr,
						 struct vm_route *r, int socketid);
int lpm_get_ip6_dst_port(int port_id, int t_vni, const struct rte_ipv6_hdr *ipv6_hdr,
						 struct vm_route *r, int socketid);

void dp_init_vm_handle_tbl(int socket_id);
void dp_map_vm_handle(void *key, uint16_t portid);
int dp_get_portid_with_vm_handle(void *key);
void dp_del_portid_with_vm_handle(void *key);

uint32_t dp_get_gw_ip4();
uint8_t* dp_get_gw_ip6();
uint32_t dp_get_dhcp_range_ip4(uint16_t portid);
uint8_t* dp_get_dhcp_range_ip6(uint16_t portid);
uint8_t* dp_get_vm_ip6(uint16_t portid);
uint32_t dp_get_vm_nat_ip(uint16_t portid);
uint16_t dp_get_vm_port_id_per_nat_ip(uint32_t nat_ip);
int dp_add_route(uint16_t portid, uint32_t vni, uint32_t t_vni, uint32_t ip,
				 uint8_t* ip6, uint8_t depth, int socketid);
int dp_del_route(uint16_t portid, uint32_t vni, uint32_t t_vni, 
				 uint32_t ip, uint8_t* ip6, uint8_t depth, int socketid);
int dp_add_route6(uint16_t portid, uint32_t vni, uint32_t t_vni, uint8_t* ipv6,
				 uint8_t* ext_ip6, uint8_t depth, int socketid);
int dp_del_route6(uint16_t portid, uint32_t vni, uint32_t t_vni, uint8_t* ipv6,
				 uint8_t* ext_ip6, uint8_t depth, int socketid);
void dp_set_dhcp_range_ip4(uint16_t portid, uint32_t ip, uint8_t depth, int socketid);
void dp_set_dhcp_range_ip6(uint16_t portid, uint8_t* ipv6, uint8_t depth, int socketid);
void dp_set_vm_ip6(uint16_t portid, uint8_t* ipv6);
void dp_set_mac(uint16_t portid);
struct rte_ether_addr *dp_get_mac(uint16_t portid);
void dp_set_neigh_mac(uint16_t portid, struct rte_ether_addr* neigh);
void dp_set_vm_nat_ip(uint16_t portid, uint32_t ip);
void dp_del_vm_nat_ip(uint16_t portid);
struct rte_ether_addr *dp_get_neigh_mac(uint16_t portid);
bool dp_is_vm_natted(uint16_t portid);
void dp_del_vm(int portid, int socketid);
int dp_get_active_vm_ports(int* act_ports);
uint8_t* dp_get_vm_machineid(uint16_t portid);
int dp_get_vm_vni(uint16_t portid);
#ifdef __cplusplus
}
#endif
#endif
