#ifndef __INCLUDE_DP_LPM_PRIV_H__
#define __INCLUDE_DP_LPM_PRIV_H__

#include <rte_rib.h>
#include "dpdk_layer.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DP_ROUTE_DHCP		-2
#define DP_ROUTE_DROP		-3

#define DP_IP_PROTO_UDP		0x11
#define DP_IP_PROTO_TCP		0x06
#define DP_IP_PROTO_ICMP	0x01
#define DP_IP6_HOP_LIMIT	0x40
#define DP_IP6_VTC_FLOW		0x60000000

#define IPV4_DP_RIB_MAX_RULES	1024


struct macip_entry {
	struct rte_ether_addr	own_mac;
	struct rte_ether_addr	neigh_mac;
	uint32_t	own_ip;
	uint32_t	neigh_ip;
	uint8_t	depth;
	uint8_t	own_ipv6[16];
	uint8_t	neigh_ipv6[16];
};

struct vm_entry {
	struct rte_rib		*ipv4_rib[DP_NB_SOCKETS];
	struct macip_entry	info;
	int					vni;
	int					machine_id;
	uint8_t				vm_ready;
};

struct vm_route {
	int		vni;
	uint8_t	nh_ipv6[16];
};

void setup_lpm(int port_id, int machine_id, int vni, const int socketid);
int lpm_get_ip4_dst_port(int port_id, int t_vni, const struct rte_ipv4_hdr *ipv4_hdr,
						 struct vm_route *r, int socketid);

uint32_t dp_get_gw_ip4();
uint8_t* dp_get_gw_ip6();
uint32_t dp_get_dhcp_range_ip4(uint16_t portid);
uint8_t* dp_get_ip6(uint16_t portid);
uint8_t* dp_get_neigh_ip6(uint16_t portid);
int dp_add_route(uint16_t portid, uint32_t vni, uint32_t t_vni, uint32_t ip,
				 uint8_t* ip6, uint8_t depth, int socketid);
void dp_set_dhcp_range_ip4(uint16_t portid, uint32_t ip, uint8_t depth, int socketid);
void dp_set_ip6(uint16_t portid, uint8_t* ipv6, uint8_t depth, int socketid);
void dp_set_neigh_ip6(uint16_t portid, uint8_t* ipv6);
void dp_set_mac(uint16_t portid);
struct rte_ether_addr *dp_get_mac(uint16_t portid);
void dp_set_neigh_mac(uint16_t portid, struct rte_ether_addr* neigh);
struct rte_ether_addr *dp_get_neigh_mac(uint16_t portid);
#ifdef __cplusplus
}
#endif
#endif
