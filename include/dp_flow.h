// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#ifndef __INCLUDE_DP_FLOW_PRIV_H__
#define __INCLUDE_DP_FLOW_PRIV_H__

#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_flow.h>
#include <rte_malloc.h>
#include "dpdk_layer.h"
#include "dp_ipaddr.h"
#include "dp_firewall.h"
#include "dp_mbuf_dyn.h"
#include "dp_refcount.h"
#include "dp_timers.h"
#include "dp_vnf.h"

#ifdef __cplusplus
extern "C" {
#endif

// arbitrary big number
#define DP_FLOW_TABLE_MAX				850000

#define DP_FLOW_VAL_AGE_CTX_CAPACITY	6

#define DP_FLOW_DEFAULT_TIMEOUT			30				/* 30 seconds */
#define DP_FLOW_TCP_EXTENDED_TIMEOUT	(60 * 60 * 24)	/* 1 day */

#define DP_FLOW_FLAG_NONE				0x00
#define DP_FLOW_FLAG_SRC_NAT			0x01
#define DP_FLOW_FLAG_DST_NAT			0x02
#define DP_FLOW_FLAG_DST_LB				0x04
#define DP_FLOW_FLAG_FIREWALL			0x08
#define DP_FLOW_FLAG_SRC_NAT64			0x10
#define DP_FLOW_FLAG_DEFAULT			0x20

#define DP_FLOW_FLAG_NF					(DP_FLOW_FLAG_SRC_NAT64 | DP_FLOW_FLAG_SRC_NAT | DP_FLOW_FLAG_DST_NAT | DP_FLOW_FLAG_DST_LB)

#define DP_FLOW_HAS_NO_FLAGS(flag)			(!(flag))
#define DP_FLOW_HAS_FLAG_SRC_NAT(flag)		((flag) & DP_FLOW_FLAG_SRC_NAT)
#define DP_FLOW_HAS_FLAG_DST_NAT(flag)		((flag) & DP_FLOW_FLAG_DST_NAT)
#define DP_FLOW_HAS_FLAG_DST_LB(flag)		((flag) & DP_FLOW_FLAG_DST_LB)
#define DP_FLOW_HAS_FLAG_FIREWALL(flag)		((flag) & DP_FLOW_FLAG_FIREWALL)
#define DP_FLOW_HAS_FLAG_SRC_NAT64(flag)	((flag) & DP_FLOW_FLAG_SRC_NAT64)
#define DP_FLOW_HAS_FLAG_DEFAULT(flag)		((flag) & DP_FLOW_FLAG_DEFAULT)

#define DP_FLOW_HAS_FLAG_NF(flag)		((flag) & DP_FLOW_FLAG_NF)

enum dp_flow_nat_type {
	DP_FLOW_NAT_TYPE_NONE,
	DP_FLOW_NAT_TYPE_VIP,
	DP_FLOW_NAT_TYPE_NETWORK_LOCAL,
	DP_FLOW_NAT_TYPE_NETWORK_NEIGH,
	DP_FLOW_NAT_AS_TARGET,
	DP_FLOW_LB_TYPE_LOCAL_NEIGH_TRAFFIC,
	DP_FLOW_LB_TYPE_RECIRC,
	DP_FLOW_LB_TYPE_FORWARD,
} __rte_packed;

enum dp_flow_tcp_state {
	DP_FLOW_TCP_STATE_NONE,
	DP_FLOW_TCP_STATE_NEW_SYN,
	DP_FLOW_TCP_STATE_NEW_SYNACK,
	DP_FLOW_TCP_STATE_ESTABLISHED,
	DP_FLOW_TCP_STATE_FINWAIT,
	DP_FLOW_TCP_STATE_RST_FIN,
};

struct flow_key {
	struct dp_ip_address l3_dst;
	uint8_t  proto;
	uint16_t port_dst;
	struct dp_ip_address l3_src;
	enum dp_vnf_type vnf_type;
	union {
		uint16_t port_src;
		uint16_t type_src; /* ICMP */
	} src;
	uint32_t vni;
} __rte_packed;
static_assert(sizeof(((struct flow_key *)0)->vnf_type) == 1,
			  "enum dp_vnf_type is unnecessarily big");

struct flow_nf_info {
	uint32_t vni;
	uint16_t icmp_err_ip_cksum;
	enum dp_flow_nat_type nat_type;
	union dp_ipv6 underlay_dst;
	uint8_t l4_type;
};

struct flow_value {
	struct flow_key	flow_key[DP_FLOW_DIR_CAPACITY];
	struct flow_age_ctx *rte_age_ctxs[DP_FLOW_VAL_AGE_CTX_CAPACITY];
	struct flow_nf_info	nf_info;
	uint64_t		timestamp;
	uint32_t		timeout_value; //actual timeout in sec = dp-service timer's resolution * timeout_value
	uint16_t		created_port_id;
	uint8_t			flow_flags;
	enum dp_fwall_action	fwall_action[DP_FLOW_DIR_CAPACITY];
	struct {
		enum dp_pkt_offload_state orig;
		enum dp_pkt_offload_state reply;
	} offload_state;
	struct {
		bool pf0;
		bool pf1;
	} incoming_flow_offloaded_flag;
	struct dp_ref	ref_count;
	union {
		enum dp_flow_tcp_state		tcp_state;
	} l4_state;
	bool			aged;
};

struct flow_age_ctx {
	struct flow_value	*cntrack;
	struct rte_flow		*rte_flow;
	uint8_t				ref_index_in_cntrack;
	uint8_t				port_id;
	struct rte_flow_action_handle *handle;
};

static __rte_always_inline
bool dp_are_flows_identical(const struct flow_key *key1, const struct flow_key *key2)
{
	static_assert(sizeof(struct flow_key) == 44, "Size of struct_flow_key has changed");
	return ((const uint64_t *)key1)[0] == ((const uint64_t *)key2)[0]
		&& ((const uint64_t *)key1)[1] == ((const uint64_t *)key2)[1]
		&& ((const uint64_t *)key1)[2] == ((const uint64_t *)key2)[2]
		&& ((const uint64_t *)key1)[3] == ((const uint64_t *)key2)[3]
		&& ((const uint64_t *)key1)[4] == ((const uint64_t *)key2)[4]
		&& ((const uint32_t *)key1)[10] == ((const uint32_t *)key2)[10];  // 8 * 5 = 40 = 4 * 10
}

int dp_get_flow(const struct flow_key *key, struct flow_value **p_flow_val);
int dp_add_flow(const struct flow_key *key, struct flow_value *flow_val);
void dp_delete_flow(const struct flow_key *key, struct flow_value *flow_val);
int dp_build_flow_key(struct flow_key *key /* out */, struct rte_mbuf *m /* in */);
void dp_invert_flow_key(const struct flow_key *key /* in */, struct flow_key *inv_key /* out */);
int dp_flow_init(int socket_id);
void dp_flow_free(void);
void dp_process_aged_flows(uint16_t port_id);
void dp_process_aged_flows_non_offload(void);
void dp_free_flow(struct dp_ref *ref);
void dp_free_network_nat_port(const struct flow_value *cntrack);
void dp_remove_nat_flows(uint16_t port_id, enum dp_flow_nat_type nat_type);
void dp_remove_neighnat_flows(uint32_t ipv4, uint32_t vni, uint16_t min_port, uint16_t max_port);
void dp_remove_iface_flows(uint16_t port_id, uint32_t ipv4, uint32_t vni);
void dp_remove_lbtarget_flows(const union dp_ipv6 *ul_addr);

hash_sig_t dp_get_conntrack_flow_hash_value(const struct flow_key *key);

int dp_add_rte_age_ctx(struct flow_value *cntrack, struct flow_age_ctx *ctx);
int dp_del_rte_age_ctx(struct flow_value *cntrack, const struct flow_age_ctx *ctx);


#ifdef __cplusplus
}
#endif
#endif
