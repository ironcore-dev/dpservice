#ifndef __INCLUDE_DP_NAT_H__
#define __INCLUDE_DP_NAT_H__

#ifdef __cplusplus
extern "C" {
#endif

#define DP_NAT_TABLE_MAX	100

// TODO: change this to a configurable value
#define DP_HORIZONTAL_NAT_MAX_ENTRY 256

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

struct horizontal_nat_entry {
	union 
	{
		uint32_t	nat_ip4;
		uint8_t		nat_ip6[16];
	} nat_ip;

	uint16_t	port_range[2];
	
	uint32_t	vni;
	uint8_t		dst_ipv6[16];

	struct horizontal_nat_entry	*next;
};

struct snat_data {
	uint32_t	vip_ip;
	uint32_t	horizontal_nat_ip;
	uint16_t	horizontal_nat_port_range[2];
};

struct network_dnat_key{
	uint32_t	nat_ip;
	uint32_t	vni;
	uint16_t	nat_port;
};

struct network_dnat_value{
	uint32_t	vm_ip;
	uint16_t	vm_port;
};

void dp_init_nat_tables(int socket_id);
void dp_del_vm_snat_ip(uint32_t vm_ip, uint32_t vni);
bool dp_is_ip_snatted(uint32_t vm_ip, uint32_t vni);
uint32_t dp_get_vm_snat_ip(uint32_t vm_ip, uint32_t vni);
int dp_set_vm_snat_ip(uint32_t vm_ip, uint32_t s_ip, uint32_t vni);

void dp_del_vm_dnat_ip(uint32_t d_ip, uint32_t vni);
bool dp_is_ip_dnatted(uint32_t d_ip, uint32_t vni);
uint32_t dp_get_vm_dnat_ip(uint32_t d_ip, uint32_t vni);
int dp_set_vm_dnat_ip(uint32_t d_ip, uint32_t vm_ip, uint32_t vni);
void dp_nat_chg_ip(struct dp_flow *df_ptr, struct rte_ipv4_hdr *ipv4_hdr,
				   struct rte_mbuf *m);

int dp_add_horizontal_nat_entry(uint32_t nat_ipv4, uint8_t *nat_ipv6, 
								uint32_t vni, uint16_t min_port, uint16_t max_port,
								uint8_t *underlay_ipv6);

int dp_del_horizontal_nat_entry(uint32_t nat_ipv4, uint8_t *nat_ipv6, 
								uint32_t vni, uint16_t min_port, uint16_t max_port);

int dp_get_horizontal_nat_underlay_ip(uint32_t nat_ipv4, uint8_t *nat_ipv6, 
								uint32_t vni, uint16_t min_port, uint16_t max_port, uint8_t *underlay_ipv6);

bool dp_is_ip_hrztl_snatted(uint32_t vm_ip, uint32_t vni);
uint32_t dp_get_vm_hrztl_snat_ip(uint32_t vm_ip, uint32_t vni);
int dp_set_vm_hrztl_snat_ip(uint32_t vm_ip, uint32_t s_ip, uint32_t vni, uint16_t min_port, uint16_t max_port);
void dp_del_vm_hrztl_snat_ip(uint32_t vm_ip, uint32_t vni);
uint16_t dp_allocate_hrztl_snat_port(uint32_t vm_ip, uint16_t vm_port, uint32_t vni);
int dp_lookup_horizontal_nat_underlay_ip(struct rte_mbuf *pkt, uint8_t *underlay_ipv6);

#ifdef __cplusplus
}
#endif
#endif