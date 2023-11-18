// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#ifndef __INCLUDE_DP_LPM_PRIV_H__
#define __INCLUDE_DP_LPM_PRIV_H__

#include <rte_rib.h>
#include <rte_rib6.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_flow.h>
#include "dpdk_layer.h"
#include "dp_mbuf_dyn.h"
#include "dp_util.h"
#include "dp_firewall.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DP_IP_PROTO_UDP		0x11
#define DP_IP_PROTO_TCP		0x06
#define DP_IP_PROTO_ICMP	0x01
#define DP_IP_PROTO_SIPSR   0x2b
#define DP_IP_PROTO_IPv4_ENCAP 0x04
#define DP_IP_PROTO_IPv6_ENCAP 0x29

#define IP6_HDR_ROUTING_TYPE_SEGMENT_ROUTING 0x04

#define DP_IP6_HOP_LIMIT	0x40
#define DP_IP6_VTC_FLOW		0x60000000

#define IPV4_DP_RIB_MAX_RULES	1024
#define IPV6_DP_RIB_MAX_RULES	1024

#define DP_LPM_ROLLBACK	true
#define DP_LPM_DHCP_IP_DEPTH	32
#define DP_LPM_DHCP_IP6_DEPTH	128

#define DP_LIST_EXT_ROUTES true
#define DP_LIST_INT_ROUTES false

struct dp_iface_route {
	uint32_t vni;
	uint8_t  nh_ipv6[16];
};

const struct dp_port *dp_get_ip4_out_port(const struct dp_port *in_port,
										  uint32_t t_vni,
										  const struct dp_flow *df,
										  struct dp_iface_route *route,
										  uint32_t *route_key);

const struct dp_port *dp_get_ip6_out_port(const struct dp_port *in_port,
										  uint32_t t_vni,
										  const struct dp_flow *df,
										  struct dp_iface_route *route);

uint32_t dp_get_gw_ip4(void);
const uint8_t *dp_get_gw_ip6(void);

int dp_add_route(const struct dp_port *port, uint32_t vni, uint32_t t_vni, uint32_t ip,
				 const uint8_t *ip6, uint8_t depth);
int dp_del_route(const struct dp_port *port, uint32_t vni, uint32_t ip, uint8_t depth);
int dp_add_route6(const struct dp_port *port, uint32_t vni, uint32_t t_vni, const uint8_t *ipv6,
				  const uint8_t *ext_ip6, uint8_t depth);
int dp_del_route6(const struct dp_port *port, uint32_t vni, const uint8_t *ipv6, uint8_t depth);
int dp_list_routes(const struct dp_port *port, uint32_t vni, bool ext_routes, struct dp_grpc_responder *responder);

int dp_lpm_reset_all_route_tables(void);
int dp_lpm_reset_route_tables(uint32_t vni);

#ifdef __cplusplus
}
#endif

#endif
