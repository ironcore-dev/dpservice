#ifndef __INCLUDE_DP_LB_H__
#define __INCLUDE_DP_LB_H__

#ifdef __cplusplus
extern "C" {
#endif

#define DP_LB_TABLE_MAX	100

#define DP_LB_OFF	0
#define DP_LB_ON	1
#define DP_LB_LB	2
#define DP_LB_DLB	3

struct lb_key {
	uint32_t	ip;
	uint32_t	vni;
};

void dp_init_lb_tables(int socket_id);
void dp_del_vm_lb_ip(uint32_t vm_ip, uint32_t vni);
bool dp_is_ip_lb(uint32_t vm_ip, uint32_t vni);
uint32_t dp_get_vm_lb_ip(uint32_t vm_ip, uint32_t vni);
void dp_set_vm_lb_ip(uint32_t vm_ip, uint32_t s_ip, uint32_t vni);


#ifdef __cplusplus
}
#endif
#endif