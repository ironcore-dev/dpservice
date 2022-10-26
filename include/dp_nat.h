#ifndef __INCLUDE_DP_NAT_H__
#define __INCLUDE_DP_NAT_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/queue.h>

#define DP_NAT_TABLE_MAX	100

// TODO: change this to a configurable value
#define DP_NETWORK_NAT_MAX_ENTRY 256

enum {
	DP_NAT_CHG_NONE,
	DP_NAT_CHG_SRC_IP,
	DP_NAT_CHG_DST_IP,
	DP_LB_CHG_UL_DST_IP,
	DP_LB_RECIRC,
};

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
};

struct network_dnat_key {
	uint32_t	nat_ip;
	uint32_t	vni;
	uint16_t	nat_port;
	uint8_t	l4_type;
};

struct network_dnat_value {
	uint32_t	vm_ip;
	uint16_t	vm_port;
};

struct nat_check_result {
	bool	is_vip_natted;
	bool	is_network_natted;
};

void dp_init_nat_tables(int socket_id);
void dp_del_vm_snat_ip(uint32_t vm_ip, uint32_t vni);
uint32_t dp_get_vm_snat_ip(uint32_t vm_ip, uint32_t vni);
int dp_set_vm_snat_ip(uint32_t vm_ip, uint32_t s_ip, uint32_t vni);

void dp_del_vm_dnat_ip(uint32_t d_ip, uint32_t vni);
bool dp_is_ip_dnatted(uint32_t d_ip, uint32_t vni);
uint32_t dp_get_vm_dnat_ip(uint32_t d_ip, uint32_t vni);
int dp_set_vm_dnat_ip(uint32_t d_ip, uint32_t vm_ip, uint32_t vni);
void dp_nat_chg_ip(struct dp_flow *df_ptr, struct rte_ipv4_hdr *ipv4_hdr,
				   struct rte_mbuf *m);

int dp_add_network_nat_entry(uint32_t nat_ipv4, uint8_t *nat_ipv6,
								uint32_t vni, uint16_t min_port, uint16_t max_port,
								uint8_t *underlay_ipv6);

int dp_del_network_nat_entry(uint32_t nat_ipv4, uint8_t *nat_ipv6,
								uint32_t vni, uint16_t min_port, uint16_t max_port);

int dp_get_network_nat_underlay_ip(uint32_t nat_ipv4, uint8_t *nat_ipv6,
								uint32_t vni, uint16_t min_port, uint16_t max_port, uint8_t *underlay_ipv6);

void dp_check_if_ip_natted(uint32_t vm_ip, uint32_t vni, struct nat_check_result *result);
uint32_t dp_get_vm_network_snat_ip(uint32_t vm_ip, uint32_t vni);
int dp_set_vm_network_snat_ip(uint32_t vm_ip, uint32_t s_ip, uint32_t vni, uint16_t min_port, uint16_t max_port);
int dp_del_vm_network_snat_ip(uint32_t vm_ip, uint32_t vni);
uint16_t dp_allocate_network_snat_port(uint32_t vm_ip, uint16_t vm_port, uint32_t vni, uint8_t l4_type);
int dp_lookup_network_nat_underlay_ip(struct rte_mbuf *pkt, uint8_t *underlay_ipv6);
int dp_remove_network_snat_port(uint32_t nat_ip, uint16_t nat_port, uint32_t vni, uint8_t l4_type);
int dp_list_nat_local_entry(struct rte_mbuf *m, struct rte_mbuf *rep_arr[], uint32_t nat_ip);
int dp_list_nat_neigh_entry(struct rte_mbuf *m, struct rte_mbuf *rep_arr[], uint32_t nat_ip);

#ifdef __cplusplus
}
#endif
#endif

