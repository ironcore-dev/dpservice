// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#ifndef __INCLUDE_DP_LB_H__
#define __INCLUDE_DP_LB_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "dp_flow.h"
#include "grpc/dp_grpc_responder.h"

#define DP_LB_TABLE_NAME			"loadbalancer_table"
#define DP_LB_ID_TABLE_NAME			"loadbalancer_id_table"
#define DP_LB_TABLE_MAX				256
#define DP_LB_MAX_IPS_PER_VIP		64
/* Needs to be a prime number at least 2xDP_LB_MAX_IPS_PER_VIP for a uniform distribution */
#define DP_LB_MAGLEV_LOOKUP_SIZE	503

struct lb_key {
	uint32_t				vni;
	struct dp_ip_address	ip;
} __attribute__((__packed__));

struct lb_port {
	uint8_t			protocol;
	rte_be16_t		port;
};

struct lb_value {
	uint8_t				lb_id[DP_LB_ID_MAX_LEN];
	struct lb_port		ports[DP_LB_MAX_PORTS];
	union dp_ipv6		back_end_ips[DP_LB_MAX_IPS_PER_VIP];
	int16_t				maglev_hash[DP_LB_MAGLEV_LOOKUP_SIZE];
	uint16_t			back_end_cnt;
	union dp_ipv6		lb_ul_addr;
};

int dp_lb_init(int socket_id);
void dp_lb_free(void);
bool dp_is_ip_lb(struct dp_flow *df, uint32_t vni);
const union dp_ipv6 *dp_lb_get_backend_ip(struct flow_key *flow_key, uint32_t vni);
bool dp_is_lb_enabled(void);
int dp_del_lb_back_ip(const void *id_key, const union dp_ipv6 *back_ip);
int dp_add_lb_back_ip(const void *id_key, const union dp_ipv6 *back_ip);
int dp_get_lb_back_ips(const void *id_key, struct dp_grpc_responder *responder);
int dp_create_lb(struct dpgrpc_lb *lb, const union dp_ipv6 *ul_ip);
int dp_delete_lb(const void *id_key);
int dp_get_lb(const void *id_key, struct dpgrpc_lb *out_lb);
int dp_list_lbs(struct dp_grpc_responder *responder);

#ifdef __cplusplus
}
#endif
#endif
