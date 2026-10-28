// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#ifndef __INCLUDE_DP_VNF_H__
#define __INCLUDE_DP_VNF_H__

#include <stdint.h>
#include <stdbool.h>
#include <rte_common.h>
#include "dp_ipaddr.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DP_VNF_TABLE_NAME			"vnf_table"
#define DP_VNF_REVERSE_TABLE_NAME	"reverse_vnf_table"

#define DP_VNF_MATCH_ALL_PORT_IDS 0xFFFF

// forward declaration as 'struct dp_grpc_responder' needs some definitions from here
struct dp_grpc_responder;

enum __rte_packed_begin dp_vnf_type {
	DP_VNF_TYPE_UNDEFINED,
	DP_VNF_TYPE_INTERFACE_IP,
	DP_VNF_TYPE_VIP,
	DP_VNF_TYPE_NAT,
	DP_VNF_TYPE_LB,
	DP_VNF_TYPE_LB_ALIAS_PFX,
	DP_VNF_TYPE_ALIAS_PFX,
} __rte_packed_end;  // for 'struct dp_flow' and 'struct flow_key'

struct dp_vnf_prefix {
	struct dp_ip_address	ol;
	uint8_t					length;
};

struct dp_vnf {
	enum dp_vnf_type		type;
	uint32_t				vni;
	uint16_t				port_id;
	struct dp_vnf_prefix	alias_pfx;
};

int dp_vnf_init(int socket_id);
void dp_vnf_free(void);

int dp_add_vnf(const union dp_ipv6 *ul_addr6, enum dp_vnf_type type,
			   uint16_t port_id, uint32_t vni, const struct dp_ip_address *pfx_ip, uint8_t prefix_len);
const struct dp_vnf *dp_get_vnf(const union dp_ipv6 *ul_addr6);
int dp_del_vnf(const union dp_ipv6 *ul_addr6);

bool dp_vnf_lbprefix_exists(uint16_t port_id, uint32_t vni, const struct dp_ip_address *prefix_ip, uint8_t prefix_len);

int dp_del_vnf_by_value(enum dp_vnf_type type, uint16_t port_id, uint32_t vni, const struct dp_ip_address *prefix_ip, uint8_t prefix_len);

int dp_list_vnf_alias_prefixes(uint16_t port_id, enum dp_vnf_type type, struct dp_grpc_responder *responder);

// forward declarations, because 'struct dp_flow' needs the definitions above
struct rte_mbuf;
struct dp_port;

// Resolve the endpoint that an incoming tunnel packet's underlay destination stands for, and
// record it in the packet's flow data. Both decap nodes need this: ipsec_decap resolves it before
// decrypting, so that it can hold the VNI against the association that matched, and ipip_decap
// needs the result to hand the packet on. Whichever gets there first pays for the lookup, the
// other reads what it left behind.
// Returns the destination port, or NULL when the address stands for no endpoint or its port is
// gone - which is a drop in either node.
struct dp_port *dp_vnf_resolve_tunnel_dst(struct rte_mbuf *m);


#ifdef __cplusplus
}
#endif

#endif
