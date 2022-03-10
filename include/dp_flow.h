#ifndef __INCLUDE_DP_FLOW_PRIV_H__
#define __INCLUDE_DP_FLOW_PRIV_H__

#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_flow.h>
#include <rte_malloc.h>
#include "dpdk_layer.h"
#include "node_api.h"

#ifdef __cplusplus
extern "C" {
#endif

#define FLOW_MAX	1*1024*1024UL

struct flow_key {
	uint32_t ip_dst;
	uint32_t ip_src;
	uint16_t port_dst;
	uint16_t port_src;
	uint16_t if_idx;
	uint8_t  proto;
} __rte_packed;

struct flow_value {
	uint16_t		installed_port;
	uint16_t		flow_state;
	rte_atomic32_t	flow_cnt;
};

struct flow_age_ctx {
	struct flow_key	fkey;
	struct rte_flow	*rteflow;
	uint16_t		port;
};

void dp_get_flow_data(struct flow_key *key, void **data);
void dp_add_flow_data(struct flow_key *key, void *data);
void dp_add_flow(struct flow_key *key);
void dp_delete_flow(struct flow_key *key);
bool dp_flow_exists(struct flow_key *key);
void dp_build_flow_key(struct flow_key *key /* out */, struct rte_mbuf *m /* in */);
void dp_init_flowtable(int socket_id);
void dp_process_aged_flows(int port_id);

#ifdef __cplusplus
}
#endif
#endif