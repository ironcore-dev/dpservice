// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#include "dp_lpm.h"
#include <rte_errno.h>
#include "dp_conf.h"
#include "dp_error.h"
#include "dp_firewall.h"
#include "dp_flow.h"
#include "dp_log.h"
#include "dp_mbuf_dyn.h"
#include "dp_port.h"
#include "dp_vni.h"
#include "grpc/dp_grpc_responder.h"

static const uint32_t dp_router_gw_ip4 = RTE_IPV4(169, 254, 0, 1);
static const union dp_ipv6 dp_router_gw_ip6 = {
	.bytes = { 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01 }
};

static __rte_always_inline int dp_lpm_fill_route_tables(const struct dp_port *port)
{
	int ret;

	ret = dp_add_route(port, port->iface.vni, 0, port->iface.cfg.own_ip, NULL, 32);
	if (DP_FAILED(ret))
		return ret;

	ret = dp_add_route6(port, port->iface.vni, 0, &port->iface.cfg.dhcp_ipv6, NULL, 128);
	if (DP_FAILED(ret))
		return ret;

	return DP_GRPC_OK;
}

int dp_lpm_reset_all_route_tables(void)
{
	const struct dp_ports *ports = dp_get_ports();
	int ret;

	if (DP_FAILED(dp_reset_all_vni_route_tables()))
		return DP_GRPC_ERR_ROUTE_RESET;

	DP_FOREACH_PORT(ports, port) {
		if (!port->iface.ready)
			continue;
		ret = dp_lpm_fill_route_tables(port);
		if (DP_FAILED(ret))
			return ret;
	}

	return DP_GRPC_OK;
}

int dp_lpm_reset_route_tables(uint32_t vni)
{
	const struct dp_ports *ports = dp_get_ports();
	int ret;

	if (DP_FAILED(dp_reset_vni_route_tables(vni))) {
		DPS_LOG_ERR("Resetting vni route tables failed", DP_LOG_VNI(vni));
		return DP_GRPC_ERR_ROUTE_RESET;
	}

	DP_FOREACH_PORT(ports, port) {
		if (!port->iface.ready || port->iface.vni != vni)
			continue;
		ret = dp_lpm_fill_route_tables(port);
		if (DP_FAILED(ret))
			return ret;
	}

	return DP_GRPC_OK;
}

uint32_t dp_get_gw_ip4(void)
{
	return dp_router_gw_ip4;
}

const union dp_ipv6 *dp_get_gw_ip6(void)
{
	return &dp_router_gw_ip6;
}

int dp_add_route(const struct dp_port *port, uint32_t vni, uint32_t t_vni, uint32_t ip,
				 const union dp_ipv6 *t_ip6, uint8_t depth)
{
	struct dp_iface_route *route = NULL;
	struct rte_rib_node *node;
	struct rte_rib *root;

	root = dp_get_vni_route4_table(vni);
	if (!root)
		return DP_GRPC_ERR_NO_VNI;

	node = rte_rib_lookup_exact(root, ip, depth);
	if (node)
		return DP_GRPC_ERR_ROUTE_EXISTS;

	node = rte_rib_insert(root, ip, depth);
	if (!node)
		return DP_GRPC_ERR_ROUTE_INSERT;

	// can only fail if node is NULL
	rte_rib_set_nh(node, port->port_id);
	/* This is an external route */
	if (port->is_pf) {
		route = rte_rib_get_ext(node);
		route->vni = t_vni;
		dp_copy_ipv6(&route->nh_ipv6, t_ip6);
	}

	return DP_GRPC_OK;
}

int dp_del_route(const struct dp_port *port, uint32_t vni, uint32_t ip, uint8_t depth)
{
	struct rte_rib_node *node;
	struct rte_rib *root;
	uint64_t next_hop;

	root = dp_get_vni_route4_table(vni);
	if (!root)
		return DP_GRPC_ERR_NO_VNI;

	node = rte_rib_lookup_exact(root, ip, depth);
	if (!node)
		return DP_GRPC_ERR_ROUTE_NOT_FOUND;

	// can only fail if node or next_hop is NULL
	rte_rib_get_nh(node, &next_hop);
	if (next_hop != port->port_id)
		return DP_GRPC_ERR_ROUTE_BAD_PORT;

	rte_rib_remove(root, ip, depth);
	return DP_GRPC_OK;
}

static __rte_always_inline bool dp_route_in_dhcp_range(const struct rte_rib_node *node,
													   const struct dp_port *port)
{
	uint32_t ipv4 = 0;
	uint8_t depth = 0;

	// both calls only fail when either param is NULL
	rte_rib_get_ip(node, &ipv4);
	rte_rib_get_depth(node, &depth);
	return port->iface.cfg.own_ip == ipv4 && depth == DP_LPM_DHCP_IP_DEPTH;
}

static int dp_list_route_entry(struct rte_rib_node *node,
							   const struct dp_port *port,
							   bool ext_routes,
							   struct dp_grpc_responder *responder)
{
	struct dpgrpc_route *reply;
	uint64_t next_hop;
	struct dp_port *dst_port;
	struct dp_iface_route *route;
	uint32_t ipv4;
	uint8_t depth;

	// can only fail when any argument is NULL
	rte_rib_get_nh(node, &next_hop);

	dst_port = dp_get_port_by_id((uint16_t)next_hop);
	if (unlikely(!dst_port))
		return DP_GRPC_ERR_NO_VM;

	if ((ext_routes && dst_port->is_pf)
		|| (!ext_routes && dst_port->port_id == port->port_id && !dp_route_in_dhcp_range(node, port))
	) {
		reply = dp_grpc_add_reply(responder);
		if (!reply)
			return DP_GRPC_ERR_OUT_OF_MEMORY;

		rte_rib_get_ip(node, &ipv4);
		rte_rib_get_depth(node, &depth);
		dp_set_ipaddr4(&reply->pfx_addr, ipv4);
		reply->pfx_length = depth;

		if (ext_routes) {
			route = (struct dp_iface_route *)rte_rib_get_ext(node);
			dp_set_ipaddr6(&reply->trgt_addr, &route->nh_ipv6);
			reply->trgt_vni = route->vni;
		}

	}
	return DP_GRPC_OK;
}

int dp_list_routes(const struct dp_port *port, uint32_t vni, bool ext_routes,
				   struct dp_grpc_responder *responder)
{
	struct rte_rib_node *node = NULL;
	struct rte_rib *root;
	int ret;

	root = dp_get_vni_route4_table(vni);
	if (!root)
		return DP_GRPC_ERR_NO_VNI;

	dp_grpc_set_multireply(responder, sizeof(struct dpgrpc_route));

	node = rte_rib_lookup_exact(root, RTE_IPV4(0, 0, 0, 0), 0);
	if (node) {
		ret = dp_list_route_entry(node, port, ext_routes, responder);
		if (DP_FAILED(ret))
			return ret;
	}

	node = NULL;  // needed to start rte_rib_get_nxt() traversal
	while ((node = rte_rib_get_nxt(root, RTE_IPV4(0, 0, 0, 0), 0, node, RTE_RIB_GET_NXT_ALL))) {
		ret = dp_list_route_entry(node, port, ext_routes, responder);
		if (DP_FAILED(ret))
			return ret;
	}

	return DP_GRPC_OK;
}

int dp_add_route6(const struct dp_port *port, uint32_t vni, uint32_t t_vni, const union dp_ipv6 *ipv6,
				  const union dp_ipv6 *t_ip6, uint8_t depth)
{
	struct dp_iface_route *route = NULL;
	struct rte_rib6_node *node;
	struct rte_rib6 *root;

	root = dp_get_vni_route6_table(vni);
	if (!root)
		return DP_GRPC_ERR_NO_VNI;

	node = rte_rib6_lookup_exact(root, ipv6->bytes, depth);
	if (node)
		return DP_GRPC_ERR_ROUTE_EXISTS;

	node = rte_rib6_insert(root, ipv6->bytes, depth);
	if (!node)
		return DP_GRPC_ERR_ROUTE_INSERT;

	// can only fail if node is NULL
	rte_rib6_set_nh(node, port->port_id);
	/* This is an external route */
	if (port->is_pf) {
		route = rte_rib6_get_ext(node);
		route->vni = t_vni;
		dp_copy_ipv6(&route->nh_ipv6, t_ip6);
	}

	return DP_GRPC_OK;
}

int dp_del_route6(const struct dp_port *port, uint32_t vni, const union dp_ipv6 *ipv6, uint8_t depth)
{
	struct rte_rib6_node *node;
	struct rte_rib6 *root;
	uint64_t next_hop;

	root = dp_get_vni_route6_table(vni);
	if (!root)
		return DP_GRPC_ERR_NO_VNI;

	node = rte_rib6_lookup_exact(root, ipv6->bytes, depth);
	if (!node)
		return DP_GRPC_ERR_ROUTE_NOT_FOUND;

	// can only fail if node or next_hop is NULL
	rte_rib6_get_nh(node, &next_hop);
	if (next_hop != port->port_id)
		return DP_GRPC_ERR_ROUTE_BAD_PORT;

	rte_rib6_remove(root, ipv6->bytes, depth);
	return DP_GRPC_OK;
}

const struct dp_port *dp_get_ip4_out_port(const struct dp_port *in_port,
										  uint32_t t_vni,
										  const struct dp_flow *df,
										  struct dp_iface_route *route,
										  uint32_t *route_key)
{
	uint32_t dst_ip = ntohl(df->dst.dst_addr);
	struct rte_rib_node *node;
	struct rte_rib *root;
	uint64_t next_hop;
	struct dp_port *dst_port;

	if (t_vni == 0)
		t_vni = in_port->iface.vni;

	root = dp_get_vni_route4_table(t_vni);
	if (!root)
		return NULL;

	node = rte_rib_lookup(root, dst_ip);
	if (!node)
		return NULL;

	if (DP_FAILED(rte_rib_get_nh(node, &next_hop)))
		return NULL;

	dst_port = dp_get_port_by_id((uint16_t)next_hop);
	if (!dst_port)
		return NULL;

	if (dst_port->is_pf)
		rte_memcpy(route, rte_rib_get_ext(node), sizeof(*route));

	if (DP_FAILED(rte_rib_get_ip(node, route_key)))
		return NULL;

	return dst_port;
}

const struct dp_port *dp_get_ip6_out_port(const struct dp_port *in_port,
										  uint32_t t_vni,
										  const struct dp_flow *df,
										  struct dp_iface_route *route,
										  uint8_t route_key[DP_IPV6_ADDR_SIZE])
{
	struct rte_rib6_node *node;
	struct rte_rib6 *root;
	uint64_t next_hop;
	struct dp_port *dst_port;

	if (t_vni == 0)
		t_vni = in_port->iface.vni;

	root = dp_get_vni_route6_table(t_vni);
	if (!root)
		return NULL;

	node = rte_rib6_lookup(root, df->dst.dst_addr6.bytes);
	if (!node)
		return NULL;

	if (DP_FAILED(rte_rib6_get_nh(node, &next_hop)))
		return NULL;

	dst_port = dp_get_port_by_id((uint16_t)next_hop);
	if (!dst_port)
		return NULL;

	if (dst_port->is_pf)
		rte_memcpy(route, rte_rib6_get_ext(node), sizeof(*route));

	if (DP_FAILED(rte_rib6_get_ip(node, route_key)))
		return NULL;

	return dst_port;
}
