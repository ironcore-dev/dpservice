#ifndef __INCLUDE_DP_FLOW_PRIV_H__
#define __INCLUDE_DP_FLOW_PRIV_H__

#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_flow.h>
#include <rte_malloc.h>
#include "dpdk_layer.h"
#include "node_api.h"
#include "dp_refcount.h"

#ifdef __cplusplus
extern "C" {
#endif

#define FLOW_MAX				(1*1024*1024UL)
#define DP_FLOW_DEFAULT_TIMEOUT	30 /* In seconds */

enum {
	DP_FLOW_DIR_ORG,
	DP_FLOW_DIR_REPLY,
	DP_FLOW_DIR_MAX,
};

enum {
	DP_FLOW_STATE_NEW,
	DP_FLOW_STATE_REPLY,
	DP_FLOW_STATE_ESTAB,
};

enum {
	DP_FLOW_STATUS_NONE,
	DP_FLOW_STATUS_SRC_NAT,
	DP_FLOW_STATUS_DST_NAT,
	DP_FLOW_STATUS_DST_LB,
};

enum {
	DP_FLOW_NAT_TYPE_NONE,
	DP_FLOW_NAT_TYPE_VIP,
	DP_FLOW_NAT_TYPE_NETWORK_LOCAL,
	DP_FLOW_NAT_TYPE_NETWORK_NEIGH,
};

enum {
	DP_FLOW_ACTION_UNSPECIFIC,
	DP_FLOW_ACTION_DROP,
};

struct flow_key {
	uint32_t ip_dst;
	uint32_t ip_src;
	uint16_t port_dst;
	union {
		uint16_t port_src;
		uint16_t type_src; /* ICMP */
	} src;
	/*TODO Add vni also to the key */
	uint8_t  proto;
} __rte_packed;

struct flow_nat_info {
	uint32_t vni;
	uint16_t icmp_err_ip_cksum;
	uint8_t nat_type;
	uint8_t underlay_dst[16];
	uint8_t l4_type;
} __rte_packed;


struct flow_value {
	struct flow_key	flow_key[DP_FLOW_DIR_MAX];
	struct flow_nat_info	nat_info;
	uint64_t		timestamp;
	rte_atomic32_t	flow_cnt;
	uint16_t		flow_status;
	uint16_t		flow_state;
	uint16_t		dir;
	uint16_t		port;
	uint8_t			lb_dst_addr6[16];
	uint8_t			action[DP_FLOW_DIR_MAX];
	struct dp_ref	ref_count;
};

struct flow_age_ctx {
	struct flow_value	*cntrack;
	struct rte_flow		*rte_flow;
	uint16_t			dir;
};

bool dp_are_flows_identical(struct flow_key *key1, struct flow_key *key2);
int dp_get_flow_data(struct flow_key *key, void **data);
void dp_add_flow_data(struct flow_key *key, void *data);
void dp_add_flow(struct flow_key *key);
void dp_delete_flow(struct flow_key *key);
bool dp_flow_exists(struct flow_key *key);
int8_t dp_build_flow_key(struct flow_key *key /* out */, struct rte_mbuf *m /* in */);
void dp_invert_flow_key(struct flow_key *key /* in / out */);
int dp_flow_init(int socket_id);
void dp_process_aged_flows(int port_id);
void dp_process_aged_flows_non_offload(void);
void dp_free_flow(struct dp_ref *ref);
void dp_free_network_nat_port(struct flow_value *cntrack);

hash_sig_t dp_get_conntrack_flow_hash_value(struct flow_key *key);

void dp_output_flow_key_info(struct flow_key *key);

#ifdef __cplusplus
}
#endif
#endif
