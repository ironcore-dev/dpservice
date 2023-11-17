#ifndef __INCLUDE_DP_VNF_H__
#define __INCLUDE_DP_VNF_H__

#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_flow.h>
#include "dp_port.h"
#include "grpc/dp_grpc_responder.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DP_VNF_MAX_TABLE_SIZE 1000
#define DP_VNF_MATCH_ALL_PORT_IDS 0xFFFF

enum vnf_type {
	DP_VNF_TYPE_UNDEFINED,
	DP_VNF_TYPE_LB_ALIAS_PFX,
	DP_VNF_TYPE_ALIAS_PFX,
	DP_VNF_TYPE_LB,
	DP_VNF_TYPE_VIP,
	DP_VNF_TYPE_NAT,
	DP_VNF_TYPE_INTERFACE_IP,
};

struct dp_vnf_prefix {
	uint32_t	ip;
	uint16_t	length;
};

struct dp_vnf_value {
	enum vnf_type		v_type;
	uint32_t			vni;
	uint16_t			portid;
	struct dp_vnf_prefix	alias_pfx;
};

int dp_vnf_init(int socket_id);
void dp_vnf_free(void);

int dp_add_vnf(const uint8_t ul_addr6[DP_VNF_IPV6_ADDR_SIZE], enum vnf_type type,
			   uint32_t vni, uint16_t port_id, uint32_t prefix_ip, uint16_t prefix_len);
const struct dp_vnf_value *dp_get_vnf_value(const uint8_t ul_addr6[DP_VNF_IPV6_ADDR_SIZE]);
int dp_del_vnf_with_addr(const uint8_t ul_addr6[DP_VNF_IPV6_ADDR_SIZE]);

int dp_list_vnf_alias_prefixes(uint16_t port_id, enum vnf_type v_type, struct dp_grpc_responder *responder);

bool dp_vnf_lbprefix_exists(uint16_t port_id, uint32_t prefix_ip, uint16_t prefix_len);

int dp_del_vnf_by_value(enum vnf_type type, uint16_t port_id, uint32_t prefix_ip, uint16_t prefix_len);

#ifdef __cplusplus
}
#endif
#endif
