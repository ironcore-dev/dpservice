#ifndef __INCLUDE_DP_LPM_PRIV_H__
#define __INCLUDE_DP_LPM_PRIV_H__

#include <rte_lpm.h>
#include "dpdk_layer.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DP_PF_PORT			 0
#define DP_ROUTE_DHCP		-2
#define DP_ROUTE_DROP		-3

#define DP_IP_PROTO_UDP		0x11
#define DP_IP_PROTO_TCP		0x06
#define DP_IP_PROTO_ICMP	0x01

#define IPV4_L3FWD_LPM_MAX_RULES	1024
#define IPV4_L3FWD_LPM_NUMBER_TBL8S	(1 << 8)

struct macip_entry {
	struct rte_ether_addr	own_mac;
	struct rte_ether_addr	neigh_mac;
	uint32_t				own_ip;
	uint32_t				neigh_ip;
	uint8_t					depth;
};

void setup_lpm(const int socketid);
int lpm_get_ip4_dst_port(const struct rte_ipv4_hdr *ipv4_hdr, int socketid);

uint32_t dp_get_ip4(uint16_t portid);
int dp_add_route(uint16_t portid, uint32_t ip, uint8_t depth, int socketid);
void dp_set_ip4(uint16_t portid, uint32_t ip, uint8_t depth, int socketid);
void dp_set_mac(uint16_t portid);
struct rte_ether_addr *dp_get_mac(uint16_t portid);
void dp_set_neigh_mac(uint16_t portid, struct rte_ether_addr* neigh);
struct rte_ether_addr *dp_get_neigh_mac(uint16_t portid);
#ifdef __cplusplus
}
#endif
#endif
