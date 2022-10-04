#ifndef __INCLUDE_DP_LB_H__
#define __INCLUDE_DP_LB_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "grpc/dp_grpc_impl.h"

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
	uint8_t		lb_id[DP_LB_ID_SIZE];
	dp_lb_port	ports[DP_LB_PORT_SIZE];
	uint32_t	back_end_ips[DP_LB_MAX_IPS_PER_VIP][4];
	uint16_t	last_sel_pos;
	uint16_t	back_end_cnt;
};

void dp_init_lb_tables(int socket_id);
bool dp_is_ip_lb(uint32_t vm_ip, uint32_t vni);
uint32_t dp_get_lb_ip(uint32_t vm_ip, uint32_t vni);
uint8_t *dp_lb_get_backend_ip(uint32_t v_ip, uint32_t vni, uint16_t port, uint16_t proto);
bool dp_is_lb_enabled();
int dp_del_lb_back_ip(void *id_key, uint8_t *back_ip);
int dp_set_lb_back_ip(void *id_key, uint8_t *back_ip, uint8_t ip_size);
void dp_get_lb_back_ips(void *id_key, struct dp_reply *rep);
int dp_create_lb(void *id_key, uint32_t v_ip, uint32_t vni, struct dp_lb_port ports[]);
int dp_delete_lb(void *id_key);
int dp_get_lb(void *id_key, dp_lb *list_lb /* out */);


#ifdef __cplusplus
}
#endif
#endif