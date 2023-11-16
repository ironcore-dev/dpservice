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
	DP_CHG_UL_DST_IP,
	DP_LB_RECIRC,
};

struct nat_key {
	uint32_t	ip;
	uint32_t	vni;
} __rte_packed;

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
	uint32_t	nat_ip;
	uint16_t	nat_port_range[2];
	uint8_t		ul_vip_ip6[16]; /* VIP underlay */
	uint8_t		ul_nat_ip6[16]; /* NAT Gateway underlay */
	uint64_t	log_timestamp;
};

struct dnat_data {
	uint32_t	dnat_ip;
};

struct netnat_portmap_key {
	uint32_t	iface_src_ip;
	uint32_t	vni;
	uint16_t	iface_src_port;
} __rte_packed;

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
} __rte_packed;

struct nat_check_result {
	bool	is_vip_natted;
	bool	is_network_natted;
};

int dp_nat_init(int socket_id);
void dp_nat_free(void);

uint32_t dp_get_iface_vip_ip(uint32_t iface_ip, uint32_t vni);
int dp_set_iface_vip_ip(uint32_t iface_ip, uint32_t vip_ip, uint32_t vni,
						const uint8_t ul_ipv6[DP_VNF_IPV6_ADDR_SIZE]);
int dp_del_iface_vip_ip(uint32_t iface_ip, uint32_t vni);

uint32_t dp_get_iface_nat_ip(uint32_t iface_ip, uint32_t vni);
int dp_set_iface_nat_ip(uint32_t iface_ip, uint32_t nat_ip, uint32_t vni, uint16_t min_port, uint16_t max_port,
						const uint8_t ul_ipv6[DP_VNF_IPV6_ADDR_SIZE]);
int dp_del_iface_nat_ip(uint32_t iface_ip, uint32_t vni);

int dp_del_dnat_ip(uint32_t d_ip, uint32_t vni);
struct dnat_data *dp_get_dnat_data(uint32_t d_ip, uint32_t vni);
int dp_set_dnat_ip(uint32_t d_ip, uint32_t dnat_ip, uint32_t vni);

void dp_nat_chg_ip(struct dp_flow *df, struct rte_ipv4_hdr *ipv4_hdr,
				   struct rte_mbuf *m);

void dp_del_vip_from_dnat(uint32_t d_ip, uint32_t vni);

int dp_add_network_nat_entry(uint32_t nat_ipv4, const uint8_t nat_ipv6[DP_VNF_IPV6_ADDR_SIZE],
							 uint32_t vni, uint16_t min_port, uint16_t max_port,
							 const uint8_t ul_ipv6[DP_VNF_IPV6_ADDR_SIZE]);

int dp_del_network_nat_entry(uint32_t nat_ipv4, const uint8_t nat_ipv6[DP_VNF_IPV6_ADDR_SIZE],
							 uint32_t vni, uint16_t min_port, uint16_t max_port);

const uint8_t *dp_get_network_nat_underlay_ip(uint32_t nat_ipv4, const uint8_t nat_ipv6[DP_VNF_IPV6_ADDR_SIZE],
											  uint32_t vni, uint16_t min_port, uint16_t max_port);

int dp_allocate_network_snat_port(struct snat_data *snat_data, struct dp_flow *df, uint32_t vni);
const uint8_t *dp_lookup_network_nat_underlay_ip(struct dp_flow *df);
int dp_remove_network_snat_port(const struct flow_value *cntrack);

int dp_list_nat_local_entries(uint32_t nat_ip, struct dp_grpc_responder *responder);
int dp_list_nat_neigh_entries(uint32_t nat_ip, struct dp_grpc_responder *responder);
struct snat_data *dp_get_iface_snat_data(uint32_t iface_ip, uint32_t vni);
void dp_del_all_neigh_nat_entries_in_vni(uint32_t vni);


#ifdef __cplusplus
}
#endif
#endif

