#ifndef __INCLUDE_DP_LB_H__
#define __INCLUDE_DP_LB_H__

#ifdef __cplusplus
extern "C" {
#endif

#define DP_LB_TABLE_MAX			100
#define DP_LB_MAX_IPS_PER_VIP	20

#define DP_LB_OFF	0
#define DP_LB_ON	1
#define DP_LB_LB	2
#define DP_LB_DLB	3

struct lb_key {
	uint32_t	ip;
	uint32_t	vni;
};

struct lb_value {
	struct rte_efd_table *vip_maglev_tbl;
	uint32_t back_end_ips[DP_LB_MAX_IPS_PER_VIP];
	uint16_t last_sel_pos;
	uint16_t back_end_cnt;
};

void dp_init_lb_tables(int socket_id);
int dp_del_lb_back_ip(uint32_t vm_ip, uint32_t back_ip, uint32_t vni);
bool dp_is_ip_lb(uint32_t vm_ip, uint32_t vni);
uint32_t dp_get_lb_ip(uint32_t vm_ip, uint32_t vni);
int dp_set_lb_back_ip(uint32_t v_ip, uint32_t back_ip, uint32_t vni);
uint32_t dp_lb_get_backend_ip(uint32_t v_ip, uint32_t vni, struct flow_key *fkey);
bool dp_is_lb_enabled();


#ifdef __cplusplus
}
#endif
#endif