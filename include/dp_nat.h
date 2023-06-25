#ifndef __INCLUDE_DP_NAT_H__
#define __INCLUDE_DP_NAT_H__


#include <sys/queue.h>
#include <rte_common.h>
#include <rte_mbuf.h>
#include "dp_flow.h"
#include "grpc/dp_grpc_responder.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DP_NAT_TABLE_MAX	100

// TODO: change this to a configurable value
#define DP_NETWORK_NAT_MAX_ENTRY	256
#define DP_NETWORK_NAT_ALL_VNI		0

enum {
	DP_NAT_CHG_NONE,
	DP_NAT_CHG_SRC_IP,
	DP_NAT_CHG_DST_IP,
	DP_NAT_CHG_UL_DST_IP,
	DP_LB_CHG_UL_DST_IP,
	DP_LB_RECIRC,
};

// TODO: key packing?
struct nat_key {
	uint32_t	ip;
	uint32_t	vni;
};

typedef struct network_nat_entry {
	union {
		uint32_t	nat_ip4;
		uint8_t		nat_ip6[16];
	} nat_ip;
	uint16_t	port_range[2];
	uint32_t	vni;
	uint8_t		dst_ipv6[16];
	TAILQ_ENTRY(network_nat_entry) entries;
} network_nat_entry;

struct snat_data {
	uint32_t	vip_ip;
	uint32_t	network_nat_ip;
	uint16_t	network_nat_port_range[2];
	uint8_t		ul_ip6[16]; /* VIP underlady */
	uint8_t		ul_nat_ip6[16]; /* NAT Gateway underlay */
};

struct dnat_data {
	uint32_t	dnat_ip;
};

struct netnat_portmap_key {
	uint32_t	vm_src_ip;
	uint32_t	vni;
	uint16_t	vm_src_port;
};

struct netnat_portmap_data {
	uint32_t	nat_ip;
	uint16_t	nat_port;
	uint16_t	flow_cnt;
};

struct netnat_portoverload_tbl_key {
	uint32_t nat_ip;
	uint16_t nat_port;
	uint32_t dst_ip;
	uint16_t dst_port;
	uint8_t	l4_type;
};

struct nat_check_result {
	bool	is_vip_natted;
	bool	is_network_natted;
};

int dp_nat_init(int socket_id);
void dp_nat_free();

int dp_del_vm_snat_ip(uint32_t vm_ip, uint32_t vni);
uint32_t dp_get_vm_snat_ip(uint32_t vm_ip, uint32_t vni);
int dp_set_vm_snat_ip(uint32_t vm_ip, uint32_t s_ip, uint32_t vni, uint8_t ul_ipv6[DP_VNF_IPV6_ADDR_SIZE]);

int dp_del_dnat_ip(uint32_t d_ip, uint32_t vni);
struct dnat_data *dp_get_dnat_data(uint32_t d_ip, uint32_t vni);
int dp_set_dnat_ip(uint32_t d_ip, uint32_t dnat_ip, uint32_t vni);

void dp_nat_chg_ip(struct dp_flow *df, struct rte_ipv4_hdr *ipv4_hdr,
				   struct rte_mbuf *m);

void dp_del_vip_from_dnat(uint32_t d_ip, uint32_t vni);

int dp_add_network_nat_entry(uint32_t nat_ipv4, uint8_t nat_ipv6[DP_VNF_IPV6_ADDR_SIZE],
								uint32_t vni, uint16_t min_port, uint16_t max_port,
								uint8_t ul_ipv6[DP_VNF_IPV6_ADDR_SIZE]);

int dp_del_network_nat_entry(uint32_t nat_ipv4, uint8_t nat_ipv6[DP_VNF_IPV6_ADDR_SIZE],
								uint32_t vni, uint16_t min_port, uint16_t max_port);

const uint8_t *dp_get_network_nat_underlay_ip(uint32_t nat_ipv4, uint8_t nat_ipv6[DP_VNF_IPV6_ADDR_SIZE],
											   uint32_t vni, uint16_t min_port, uint16_t max_port);

uint32_t dp_get_vm_network_snat_ip(uint32_t vm_ip, uint32_t vni);
int dp_set_vm_network_snat_ip(uint32_t vm_ip, uint32_t s_ip, uint32_t vni, uint16_t min_port, uint16_t max_port,
							  uint8_t ul_ipv6[DP_VNF_IPV6_ADDR_SIZE]);
int dp_del_vm_network_snat_ip(uint32_t vm_ip, uint32_t vni);
int dp_allocate_network_snat_port(struct dp_flow *df, uint32_t vni);
const uint8_t *dp_lookup_network_nat_underlay_ip(struct dp_flow *df);
int dp_remove_network_snat_port(struct flow_value *cntrack);
int dp_list_nat_local_entries(uint32_t nat_ip, struct dp_grpc_responder *responder);
int dp_list_nat_neigh_entries(uint32_t nat_ip, struct dp_grpc_responder *responder);
struct snat_data *dp_get_vm_snat_data(uint32_t vm_ip, uint32_t vni);
void dp_del_all_neigh_nat_entries_in_vni(uint32_t vni);


#ifdef __cplusplus
}
#endif
#endif

