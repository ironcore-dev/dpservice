#ifndef __INCLUDE_DP_FLOW_PRIV_H__
#define __INCLUDE_DP_FLOW_PRIV_H__
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_flow.h>
#include <rte_malloc.h>
#include "dpdk_layer.h"
#include "dp_mbuf_dyn.h"
#include "dp_refcount.h"
#include "dp_timers.h"

#ifdef __cplusplus
extern "C" {
#endif

#define FLOW_MAX						(1*1024*1024UL)

#define DP_FLOW_VAL_AGE_CTX_CAPACITY	5

#define DP_FLOW_DEFAULT_TIMEOUT			30				/* 30 seconds */
#define DP_FLOW_TCP_EXTENDED_TIMEOUT	(60 * 60 * 24)	/* 1 day */

#define DP_FLOW_STATUS_FLAG_NONE		0x00
#define DP_FLOW_STATUS_FLAG_SRC_NAT		0x01
#define DP_FLOW_STATUS_FLAG_DST_NAT		0x02
#define DP_FLOW_STATUS_FLAG_DST_LB		0x04
#define DP_FLOW_STATUS_FLAG_FIREWALL	0x08
#define DP_FLOW_STATUS_FLAG_DEFAULT		0x10

#define DP_FLOW_STATUS_FLAG_NF			(DP_FLOW_STATUS_FLAG_SRC_NAT | DP_FLOW_STATUS_FLAG_DST_NAT | DP_FLOW_STATUS_FLAG_DST_LB)

#define DP_IS_FLOW_STATUS_FLAG_NONE(flag)		(!(flag))
#define DP_IS_FLOW_STATUS_FLAG_SRC_NAT(flag)	((flag) & DP_FLOW_STATUS_FLAG_SRC_NAT)
#define DP_IS_FLOW_STATUS_FLAG_DST_NAT(flag)	((flag) & DP_FLOW_STATUS_FLAG_DST_NAT)
#define DP_IS_FLOW_STATUS_FLAG_DST_LB(flag)	((flag) & DP_FLOW_STATUS_FLAG_DST_LB)
#define DP_IS_FLOW_STATUS_FLAG_FIREWALL(flag)	((flag) & DP_FLOW_STATUS_FLAG_FIREWALL)
#define DP_IS_FLOW_STATUS_FLAG_DEFAULT(flag)	((flag) & DP_FLOW_STATUS_FLAG_DEFAULT)

 #define DP_IS_FLOW_STATUS_FLAG_NF(flag)		((flag) & DP_FLOW_STATUS_FLAG_NF)


enum {
	DP_FLOW_DIR_ORG,
	DP_FLOW_DIR_REPLY,
	DP_FLOW_DIR_CAPACITY,
};

enum {
	DP_FLOW_STATE_NEW,
	DP_FLOW_STATE_ESTABLISHED,
};


enum {
	DP_FLOW_NAT_TYPE_NONE,
	DP_FLOW_NAT_TYPE_VIP,
	DP_FLOW_NAT_TYPE_NETWORK_LOCAL,
	DP_FLOW_NAT_TYPE_NETWORK_NEIGH,
	DP_FLOW_NAT_AS_TARGET,
	DP_FLOW_LB_TYPE_LOCAL_NEIGH_TRAFFIC,
	DP_FLOW_LB_TYPE_RECIRC,
	DP_FLOW_LB_TYPE_FORWARD,
};

enum {
	DP_FLOW_ACTION_UNSPECIFIC,
	DP_FLOW_ACTION_DROP,
};

enum dp_flow_tcp_state {
	DP_FLOW_TCP_STATE_NONE,
	DP_FLOW_TCP_STATE_NEW_SYN,
	DP_FLOW_TCP_STATE_NEW_SYNACK,
	DP_FLOW_TCP_STATE_ESTABLISHED,
	DP_FLOW_TCP_STATE_FINWAIT,
	DP_FLOW_TCP_STATE_RST_FIN,
};

enum dp_flow_offload_state {
	DP_FLOW_NON_OFFLOAD,
	DP_FLOW_OFFLOAD_INSTALL,
	DP_FLOW_OFFLOADED,
};

struct flow_key {
	uint32_t ip_dst;
	uint32_t ip_src;
	uint16_t port_dst;
	union {
		uint16_t port_src;
		uint16_t type_src; /* ICMP */
	} src;
	uint32_t vni;
	uint8_t  proto;
	uint8_t  vnf;
} __rte_packed;

struct flow_nf_info {
	uint32_t vni;
	uint16_t icmp_err_ip_cksum;
	uint8_t nat_type;
	uint8_t underlay_dst[16];
	uint8_t l4_type;
} __rte_packed;


struct flow_value {
	struct flow_key	flow_key[DP_FLOW_DIR_CAPACITY];
	struct flow_age_ctx *rte_age_ctxs[DP_FLOW_VAL_AGE_CTX_CAPACITY];
	struct flow_nf_info	nf_info;
	uint64_t		timestamp;
	uint32_t		timeout_value; //actual timeout in sec = dp-service timer's resolution * timeout_value
	uint16_t		created_port_id;
	uint8_t			flow_status; // record if a flow has status associated with it
	uint8_t			fwall_action[DP_FLOW_DIR_CAPACITY];
	struct {
		uint8_t orig : 4;
		uint8_t reply : 4;
	} offload_flags;
	struct {
		uint8_t pf0 : 4;
		uint8_t pf1 : 4;
	} incoming_flow_offloaded_flag;
	struct dp_ref	ref_count;
	union {
		enum dp_flow_tcp_state		tcp_state;
	} l4_state;

	uint8_t			aged : 2;

};

struct flow_age_ctx {
	struct flow_value	*cntrack;
	struct rte_flow		*rte_flow;
	uint8_t				ref_index_in_cntrack;
	uint8_t				port_id;
	struct rte_flow_action_handle *handle;

};

bool dp_are_flows_identical(struct flow_key *key1, struct flow_key *key2);
int dp_get_flow_data(struct flow_key *key, void **data);
// TODO(plague): followup PR to actually check this value
int dp_add_flow_data(struct flow_key *key, void *data);
// TODO(plague): followup PR to actually check this value (and maybe rename to _key to match delete)
int dp_add_flow(struct flow_key *key);
void dp_delete_flow_key(struct flow_key *key);
int dp_build_flow_key(struct flow_key *key /* out */, struct rte_mbuf *m /* in */);
void dp_invert_flow_key(struct flow_key *key /* in */, struct flow_key *inv_key /* out */);
int dp_flow_init(int socket_id);
void dp_flow_free(void);
void dp_process_aged_flows(int port_id);
void dp_process_aged_flows_non_offload(void);
void dp_free_flow(struct dp_ref *ref);
void dp_free_network_nat_port(struct flow_value *cntrack);
void dp_remove_nat_flows(uint16_t port_id, int nat_type);  // TODO create proper enum!
void dp_remove_neighnat_flows(uint32_t ipv4, uint32_t vni, uint16_t min_port, uint16_t max_port);

hash_sig_t dp_get_conntrack_flow_hash_value(struct flow_key *key);

int dp_add_rte_age_ctx(struct flow_value *cntrack, struct flow_age_ctx *ctx);
int dp_del_rte_age_ctx(struct flow_value *cntrack, struct flow_age_ctx *ctx);


#ifdef __cplusplus
}
#endif
#endif
