#ifndef __INCLUDE_DP_NAT_H__
#define __INCLUDE_DP_NAT_H__

#ifdef __cplusplus
extern "C" {
#endif

#define DP_NAT_TABLE_MAX	100

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

#ifdef __cplusplus
}
#endif
#endif