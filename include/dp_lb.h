// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#ifndef __INCLUDE_DP_LB_H__
#define __INCLUDE_DP_LB_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "dp_flow.h"
#include "grpc/dp_grpc_responder.h"

#define DP_LB_TABLE_MAX			256
#define DP_LB_MAX_IPS_PER_VIP	64

#define DP_LB_OFF	0
#define DP_LB_ON	1
#define DP_LB_LB	2
#define DP_LB_DLB	3

struct lb_key {
	union {
		uint32_t	v4;
		uint8_t		v6[DP_IPV6_ADDR_SIZE];
	} ip;
	uint32_t	ip_type;
	uint32_t	vni;
} __rte_packed;

struct lb_port {
	uint8_t			protocol;
	rte_be16_t		port;
};

struct lb_value {
	uint8_t				lb_id[DP_LB_ID_MAX_LEN];
	struct lb_port		ports[DP_LB_MAX_PORTS];
	uint32_t			back_end_ips[DP_LB_MAX_IPS_PER_VIP][4];
	uint16_t			last_sel_pos;
	uint16_t			back_end_cnt;
	uint8_t				lb_ul_addr[DP_VNF_IPV6_ADDR_SIZE];
};

int dp_lb_init(int socket_id);
void dp_lb_free(void);
bool dp_is_ip_lb(struct dp_flow *df, uint32_t vni);
uint8_t *dp_lb_get_backend_ip(struct flow_key *fkey, uint32_t vni);
bool dp_is_lb_enabled(void);
int dp_del_lb_back_ip(const void *id_key, const uint8_t *back_ip);
int dp_add_lb_back_ip(const void *id_key, const uint8_t *back_ip, uint8_t ip_size);
int dp_get_lb_back_ips(const void *id_key, struct dp_grpc_responder *responder);
int dp_create_lb(struct dpgrpc_lb *lb, const uint8_t *ul_ip);
int dp_delete_lb(const void *id_key);
int dp_get_lb(const void *id_key, struct dpgrpc_lb *out_lb);

#ifdef __cplusplus
}
#endif
#endif
