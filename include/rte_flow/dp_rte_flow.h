#ifndef __INCLUDE_DP_RTE_FLOW_H__
#define __INCLUDE_DP_RTE_FLOW_H__

#ifdef __cplusplus
extern "C"
{
#endif

#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_flow.h>

#include "dp_log.h"
#include "dp_lpm.h"
#include "dp_mbuf_dyn.h"

#define DP_FLOW_TYPE_LOCAL		1
#define DP_FLOW_TYPE_OUTGOING	2
#define DP_FLOW_TYPE_INCOMING	3

#define DP_FLOW_WEST_EAST		0
#define DP_FLOW_SOUTH_NORTH		1

#define DP_L4_PORT_DIR_SRC 1
#define DP_L4_PORT_DIR_DST 2

#define DP_IP_ICMP_TYPE_ERROR 3

#define DP_IP_ICMP_CODE_DST_PROTO_UNREACHABLE 2
#define DP_IP_ICMP_CODE_DST_PORT_UNREACHABLE 3
#define DP_IP_ICMP_CODE_FRAGMENT_NEEDED 4

enum {
	DP_RTE_FLOW_DEFAULT_GROUP,
	DP_RTE_FLOW_CAPTURE_GROUP,
	DP_RTE_FLOW_VNET_GROUP,
};

struct dp_icmp_err_ip_info {
	struct rte_ipv4_hdr *err_ipv4_hdr;
	rte_be16_t	l4_src_port;
	rte_be16_t	l4_dst_port;
};

// TODO optimize and maybe move
void dp_get_icmp_err_ip_hdr(struct rte_mbuf *m, struct dp_icmp_err_ip_info *err_ip_info);

void dp_change_icmp_err_l4_src_port(struct rte_mbuf *m, struct dp_icmp_err_ip_info *err_ip_info, uint16_t new_val);
void dp_change_l4_hdr_port(struct rte_mbuf *m, uint8_t port_type, uint16_t new_val);
void dp_change_icmp_identifier(struct rte_mbuf *m, uint16_t new_val);

int dp_destroy_rte_flow_agectx(struct flow_age_ctx *agectx);

struct rte_flow *dp_install_rte_flow(uint16_t port_id,
									 const struct rte_flow_attr *attr,
									 const struct rte_flow_item pattern[],
									 const struct rte_flow_action actions[]);

#ifdef __cplusplus
}
#endif

#endif
