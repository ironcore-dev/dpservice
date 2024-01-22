// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#include "grpc/dp_grpc_impl.h"
#include <time.h>
#include "dp_conf.h"
#include "dp_error.h"
#include "dp_flow.h"
#include "dp_lb.h"
#include "dp_log.h"
#include "dp_lpm.h"
#include "dp_nat.h"
#include "dp_version.h"
#ifdef ENABLE_VIRTSVC
#	include "dp_virtsvc.h"
#endif
#include "dp_iface.h"
#include "dp_vnf.h"
#include "dp_vni.h"
#include "dpdk_layer.h"
#include "grpc/dp_grpc_api.h"
#include "grpc/dp_grpc_responder.h"
#include "monitoring/dp_monitoring.h"
#include "rte_flow/dp_rte_flow_capture.h"

static uint32_t pfx_counter = 0;

static __rte_always_inline void dp_generate_underlay_ipv6(uint8_t route[DP_VNF_IPV6_ADDR_SIZE])
{
	rte_be32_t local;
	uint8_t random_byte;

	/* First 8 bytes for host */
	rte_memcpy(route, dp_conf_get_underlay_ip(), DP_VNF_IPV6_ADDR_SIZE);
	/* Following 2 bytes for kernel routing and 1 byte reserved */
	memset(route + 8, 0, 3);

#ifdef ENABLE_STATIC_UNDERLAY_IP
	random_byte = 1;
#else
	random_byte = (uint8_t)(rand() % 256);
#endif

	/* 1 byte random value */
	rte_memcpy(route + 11, &random_byte, 1);

#ifndef ENABLE_STATIC_UNDERLAY_IP
	/* Start the counter from a random value as well to increase the randomness of the address */
	if (pfx_counter == 0)
		pfx_counter = rand() % 256;
#endif

	pfx_counter++;
	local = htonl(pfx_counter);

	/* 4 byte counter */
	rte_memcpy(route + 12, &local, 4);
}

static int dp_create_vnf_route(uint8_t ul_addr6[DP_VNF_IPV6_ADDR_SIZE] /* out */,
							   enum dp_vnf_type type, uint32_t vni, const struct dp_port *port,
							   struct dp_ip_address *pfx_ip, uint8_t prefix_len)
{
	dp_generate_underlay_ipv6(ul_addr6);
	return dp_add_vnf(ul_addr6, type, port->port_id, vni, pfx_ip, prefix_len);
}

static int dp_process_create_lb(struct dp_grpc_responder *responder)
{
	struct dpgrpc_lb *request = &responder->request.add_lb;
	struct dpgrpc_ul_addr *reply = dp_grpc_single_reply(responder);
	struct dp_ip_address pfx_ip = {
		.ip_type = request->addr.ip_type
	};

	uint8_t ul_addr6[DP_VNF_IPV6_ADDR_SIZE];
	int ret = DP_GRPC_OK;

	if (request->addr.ip_type == RTE_ETHER_TYPE_IPV4 || request->addr.ip_type == RTE_ETHER_TYPE_IPV6) {
		if (DP_FAILED(dp_create_vnf_route(ul_addr6, DP_VNF_TYPE_LB, request->vni, dp_get_pf0(), &pfx_ip, 0))) {
			ret = DP_GRPC_ERR_VNF_INSERT;
			goto err;
		}
		ret = dp_create_lb(request, ul_addr6);
		if (DP_FAILED(ret))
			goto err_vnf;
		if (DP_FAILED(dp_create_vni_route_tables(request->vni, dp_get_pf0()->socket_id))) {
			ret = DP_GRPC_ERR_VNI_INIT4;
			goto err_lb;
		}
	} else {
		ret = DP_GRPC_ERR_BAD_IPVER;
		goto err;
	}
	rte_memcpy(reply->addr6, ul_addr6, sizeof(reply->addr6));
	return DP_GRPC_OK;

err_lb:
	dp_delete_lb((void *)request->lb_id);
err_vnf:
	dp_del_vnf(ul_addr6);
err:
	return ret;
}

static int dp_process_delete_lb(struct dp_grpc_responder *responder)
{
	struct dpgrpc_lb_id *request = &responder->request.del_lb;
	struct dpgrpc_lb lb;
	int ret;

	ret = dp_get_lb(request->lb_id, &lb);
	if (DP_FAILED(ret))
		return ret;

	dp_del_vnf(lb.ul_addr6);

	ret = dp_delete_lb(request->lb_id);
	if (DP_FAILED(ret))
		return ret;

	if (DP_FAILED(dp_delete_vni_route_tables(lb.vni)))
		return DP_GRPC_ERR_VNI_FREE4;

	return DP_GRPC_OK;
}

static int dp_process_get_lb(struct dp_grpc_responder *responder)
{
	struct dpgrpc_lb_id *request = &responder->request.del_lb;
	struct dpgrpc_lb *reply = dp_grpc_single_reply(responder);

	return dp_get_lb(request->lb_id, reply);
}

static int dp_process_create_lbtarget(struct dp_grpc_responder *responder)
{
	struct dpgrpc_lb_target *request = &responder->request.add_lbtrgt;

	if (request->addr.ip_type == RTE_ETHER_TYPE_IPV6)
		return dp_add_lb_back_ip(request->lb_id, request->addr.ipv6, sizeof(request->addr.ipv6));
	else
		return DP_GRPC_ERR_BAD_IPVER;
}

static int dp_process_delete_lbtarget(struct dp_grpc_responder *responder)
{
	struct dpgrpc_lb_target *request = &responder->request.del_lbtrgt;

	if (request->addr.ip_type == RTE_ETHER_TYPE_IPV6)
		return dp_del_lb_back_ip(request->lb_id, request->addr.ipv6);
	else
		return DP_GRPC_ERR_BAD_IPVER;
}

static int dp_process_initialize(__rte_unused struct dp_grpc_responder *responder)
{
	dp_del_all_neigh_nat_entries_in_vni(DP_NETWORK_NAT_ALL_VNI);
	return dp_lpm_reset_all_route_tables();
}

static int dp_process_check_vniinuse(struct dp_grpc_responder *responder)
{
	struct dpgrpc_vni *request = &responder->request.vni_in_use;
	struct dpgrpc_vni_in_use *reply = dp_grpc_single_reply(responder);

	if (request->type == DP_VNI_IPV4) {
		reply->in_use = dp_is_vni_route_table_available(request->vni, IPPROTO_IPIP);
	} else if (request->type == DP_VNI_IPV6) {
		reply->in_use = dp_is_vni_route_table_available(request->vni, IPPROTO_IPV6);
	} else
		return DP_GRPC_ERR_WRONG_TYPE;

	return DP_GRPC_OK;
}

static int dp_process_create_fwrule(struct dp_grpc_responder *responder)
{
	struct dpgrpc_fwrule *request = &responder->request.add_fwrule;
	struct dp_port *port;

	port = dp_get_port_with_iface_id(request->iface_id);
	if (!port)
		return DP_GRPC_ERR_NO_VM;

	if (dp_get_firewall_rule(request->rule.rule_id, port))
		return DP_GRPC_ERR_ALREADY_EXISTS;

	if (request->rule.action == DP_FWALL_DROP)
		return DP_GRPC_ERR_NO_DROP_SUPPORT;

	if (DP_FAILED(dp_add_firewall_rule(&request->rule, port)))
		return DP_GRPC_ERR_OUT_OF_MEMORY;

	return DP_GRPC_OK;
}

static int dp_process_get_fwrule(struct dp_grpc_responder *responder)
{
	struct dpgrpc_fwrule_id *request = &responder->request.get_fwrule;
	struct dpgrpc_fwrule_info *reply = dp_grpc_single_reply(responder);

	struct dp_port *port;
	struct dp_fwall_rule *rule;

	port = dp_get_port_with_iface_id(request->iface_id);
	if (!port)
		return DP_GRPC_ERR_NO_VM;

	rule = dp_get_firewall_rule(request->rule_id, port);
	if (!rule)
		return DP_GRPC_ERR_NOT_FOUND;

	reply->rule = *rule;
	return DP_GRPC_OK;
}

static int dp_process_delete_fwrule(struct dp_grpc_responder *responder)
{
	struct dpgrpc_fwrule_id *request = &responder->request.del_fwrule;
	struct dp_port *port;

	port = dp_get_port_with_iface_id(request->iface_id);
	if (!port)
		return DP_GRPC_ERR_NO_VM;

	if (DP_FAILED(dp_delete_firewall_rule(request->rule_id, port)))
		return DP_GRPC_ERR_NOT_FOUND;

	return DP_GRPC_OK;
}

static int dp_process_reset_vni(struct dp_grpc_responder *responder)
{
	struct dpgrpc_vni *request = &responder->request.vni_reset;

	if (request->type == DP_VNI_BOTH)
		return dp_lpm_reset_route_tables(request->vni);
	else
		return DP_GRPC_ERR_WRONG_TYPE;
}

static int dp_process_create_vip(struct dp_grpc_responder *responder)
{
	struct dpgrpc_vip *request = &responder->request.add_vip;
	struct dpgrpc_ul_addr *reply = dp_grpc_single_reply(responder);

	uint8_t ul_addr6[DP_VNF_IPV6_ADDR_SIZE];
	struct dp_ip_address pfx_ip = {
		.ip_type = request->addr.ip_type
	};
	uint32_t iface_ip, iface_vni;
	struct dp_port *port;
	uint32_t vip;
	int ret;

	port = dp_get_port_with_iface_id(request->iface_id);
	if (!port) {
		ret = DP_GRPC_ERR_NO_VM;
		goto err;
	}

	if (request->addr.ip_type == RTE_ETHER_TYPE_IPV4) {
		iface_ip = port->iface.cfg.own_ip;
		iface_vni = port->iface.vni;
		if (DP_FAILED(dp_create_vnf_route(ul_addr6, DP_VNF_TYPE_VIP, iface_vni, port, &pfx_ip, 0))) {
			ret = DP_GRPC_ERR_VNF_INSERT;
			goto err;
		}
		vip = request->addr.ipv4;
		ret = dp_set_iface_vip_ip(iface_ip, vip, iface_vni, ul_addr6);
		if (DP_FAILED(ret))
			goto err_vnf;

		ret = dp_set_dnat_ip(vip, iface_ip, iface_vni);
		if (DP_FAILED(ret))
			goto err_snat;

		rte_memcpy(reply->addr6, ul_addr6, sizeof(reply->addr6));
	} else {
		ret = DP_GRPC_ERR_BAD_IPVER;
		goto err;
	}
	return DP_GRPC_OK;

err_snat:
	dp_del_iface_vip_ip(iface_ip, iface_vni);
err_vnf:
	dp_del_vnf(ul_addr6);
err:
	return ret;
}

static int dp_process_delete_vip(struct dp_grpc_responder *responder)
{
	struct dpgrpc_iface_id *request = &responder->request.del_vip;
	struct dpgrpc_vip *reply = dp_grpc_single_reply(responder);

	struct dp_port *port;
	struct snat_data *s_data;
	uint32_t iface_ip, iface_vni;

	port = dp_get_port_with_iface_id(request->iface_id);
	if (!port)
		return DP_GRPC_ERR_NO_VM;

	iface_ip = port->iface.cfg.own_ip;
	iface_vni = port->iface.vni;

	s_data = dp_get_iface_snat_data(iface_ip, iface_vni);
	if (!s_data || !s_data->vip_ip)
		return DP_GRPC_ERR_SNAT_NO_DATA;

	dp_del_vnf(s_data->ul_vip_ip6);

	reply->addr.ip_type = RTE_ETHER_TYPE_IPV4;
	reply->addr.ipv4 = s_data->vip_ip;

	// always delete, i.e. do not use dp_del_vip_from_dnat(),
	// because 1:1 VIP is not shared with anything
	dp_del_dnat_ip(s_data->vip_ip, iface_vni);
	dp_del_iface_vip_ip(iface_ip, iface_vni);
	dp_remove_nat_flows(port->port_id, DP_FLOW_NAT_TYPE_VIP);
	return DP_GRPC_OK;
}

static int dp_process_get_vip(struct dp_grpc_responder *responder)
{
	struct dpgrpc_iface_id *request = &responder->request.get_vip;
	struct dpgrpc_vip *reply = dp_grpc_single_reply(responder);

	struct dp_port *port;
	struct snat_data *s_data;

	port = dp_get_port_with_iface_id(request->iface_id);
	if (!port)
		return DP_GRPC_ERR_NO_VM;

	s_data = dp_get_iface_snat_data(port->iface.cfg.own_ip, port->iface.vni);
	if (!s_data || !s_data->vip_ip)
		return DP_GRPC_ERR_SNAT_NO_DATA;

	reply->addr.ip_type = RTE_ETHER_TYPE_IPV4;
	reply->addr.ipv4 = s_data->vip_ip;
	rte_memcpy(reply->ul_addr6, s_data->ul_vip_ip6, sizeof(reply->ul_addr6));
	return DP_GRPC_OK;
}

static int dp_process_create_lbprefix(struct dp_grpc_responder *responder)
{
	struct dpgrpc_prefix *request = &responder->request.add_lbpfx;
	struct dpgrpc_route *reply = dp_grpc_single_reply(responder);

	struct dp_port *port;
	uint8_t ul_addr6[DP_VNF_IPV6_ADDR_SIZE];

	if (request->addr.ip_type != RTE_ETHER_TYPE_IPV4 && request->addr.ip_type != RTE_ETHER_TYPE_IPV6)
		return DP_GRPC_ERR_BAD_IPVER;

	port = dp_get_port_with_iface_id(request->iface_id);
	if (!port)
		return DP_GRPC_ERR_NO_VM;

	if (dp_vnf_lbprefix_exists(port->port_id, port->iface.vni, &request->addr, request->length))
		return DP_GRPC_ERR_ALREADY_EXISTS;

	if (DP_FAILED(dp_create_vnf_route(ul_addr6, DP_VNF_TYPE_LB_ALIAS_PFX, port->iface.vni, port, &request->addr, request->length)))
		return DP_GRPC_ERR_VNF_INSERT;

	rte_memcpy(reply->trgt_addr.ipv6, ul_addr6, sizeof(reply->trgt_addr.ipv6));
	return DP_GRPC_OK;
}

static int dp_process_delete_lbprefix(struct dp_grpc_responder *responder)
{
	struct dpgrpc_prefix *request = &responder->request.del_lbpfx;
	struct dp_port *port;

	struct dp_vnf target_vnf = {
		.type = DP_VNF_TYPE_LB_ALIAS_PFX,
		.alias_pfx.length = request->length,
	};

	if (request->addr.ip_type != RTE_ETHER_TYPE_IPV4 && request->addr.ip_type != RTE_ETHER_TYPE_IPV6)
		return DP_GRPC_ERR_BAD_IPVER;

	port = dp_get_port_with_iface_id(request->iface_id);
	if (!port)
		return DP_GRPC_ERR_NO_VM;

	target_vnf.port_id = port->port_id;
	target_vnf.vni = port->iface.vni;
	dp_assign_ip_address(&target_vnf.alias_pfx.ol, &request->addr);

	return dp_del_vnf_by_value(&target_vnf);
}

static int dp_process_create_prefix(struct dp_grpc_responder *responder)
{
	struct dpgrpc_prefix *request = &responder->request.add_pfx;
	struct dpgrpc_ul_addr *reply = dp_grpc_single_reply(responder);

	uint8_t ul_addr6[DP_VNF_IPV6_ADDR_SIZE];
	struct dp_port *port;
	uint32_t iface_vni;
	int ret;

	port = dp_get_port_with_iface_id(request->iface_id);
	if (!port)
		return DP_GRPC_ERR_NO_VM;

	iface_vni = port->iface.vni;
	if (request->addr.ip_type == RTE_ETHER_TYPE_IPV4) {
		ret = dp_add_route(port, iface_vni, 0, request->addr.ipv4, NULL, request->length);
		if (DP_FAILED(ret))
			return ret;

		if (DP_FAILED(dp_create_vnf_route(ul_addr6, DP_VNF_TYPE_ALIAS_PFX, iface_vni, port, &request->addr, request->length))) {
			dp_del_route(port, iface_vni, request->addr.ipv4, request->length);
			return DP_GRPC_ERR_VNF_INSERT;
		}
	} else if (request->addr.ip_type == RTE_ETHER_TYPE_IPV6) {
		ret = dp_add_route6(port, iface_vni, 0, request->addr.ipv6, NULL, request->length);
		if (DP_FAILED(ret))
			return ret;

		if (DP_FAILED(dp_create_vnf_route(ul_addr6, DP_VNF_TYPE_ALIAS_PFX, iface_vni, port, &request->addr, request->length))) {
			dp_del_route6(port, iface_vni, request->addr.ipv6, request->length);
			return DP_GRPC_ERR_VNF_INSERT;
		}
	} else
		return DP_GRPC_ERR_BAD_IPVER;
	rte_memcpy(reply->addr6, ul_addr6, sizeof(reply->addr6));
	return DP_GRPC_OK;
}

static int dp_process_delete_prefix(struct dp_grpc_responder *responder)
{
	struct dpgrpc_prefix *request = &responder->request.del_pfx;
	struct dp_port *port;
	int ret, ret2;

	struct dp_vnf target_vnf = {
		.type = DP_VNF_TYPE_ALIAS_PFX,
		.alias_pfx.length = request->length,
	};

	port = dp_get_port_with_iface_id(request->iface_id);
	if (!port)
		return DP_GRPC_ERR_NO_VM;

	if (request->addr.ip_type == RTE_ETHER_TYPE_IPV4) {
		ret = dp_del_route(port, port->iface.vni, request->addr.ipv4, request->length);
		// ignore the error and try to delete the vnf entry anyway
	} else if (request->addr.ip_type == RTE_ETHER_TYPE_IPV6) {
		ret = dp_del_route6(port, port->iface.vni, request->addr.ipv6, request->length);
		// ignore the error and try to delete the vnf entry anyway
	} else
		return DP_GRPC_ERR_BAD_IPVER;

	target_vnf.port_id = port->port_id;
	target_vnf.vni = port->iface.vni;

	dp_assign_ip_address(&target_vnf.alias_pfx.ol, &request->addr);
	ret2 = dp_del_vnf_by_value(&target_vnf);
	return DP_FAILED(ret) ? ret : ret2;
}

static int dp_process_create_interface(struct dp_grpc_responder *responder)
{
	struct dpgrpc_iface *request = &responder->request.add_iface;
	struct dpgrpc_vf_pci *reply = dp_grpc_single_reply(responder);

	struct dp_port *port;
	uint8_t ul_addr6[DP_VNF_IPV6_ADDR_SIZE];
	struct dp_ip_address pfx_ip = {
		.ip_type = RTE_ETHER_TYPE_IPV4 // Just pick a random valid type, not relevant for this VNF
	};
	int ret = DP_GRPC_OK;

	port = dp_get_port_by_name(request->pci_name);
	if (!port) {
		ret = DP_GRPC_ERR_NOT_FOUND;
		goto err;
	}
	if (port->allocated) {
		ret = DP_GRPC_ERR_ALREADY_EXISTS;
		goto err;
	}
	if (DP_FAILED(dp_create_vnf_route(ul_addr6, DP_VNF_TYPE_INTERFACE_IP, request->vni, port, &pfx_ip, 0))) {
		ret = DP_GRPC_ERR_VNF_INSERT;
		goto err;
	}
	if (DP_FAILED(dp_map_iface_id(request->iface_id, port))) {
		ret = DP_GRPC_ERR_VM_HANDLE;
		goto err_vnf;
	}
	if (DP_FAILED(dp_setup_iface(port, request->vni))) {
		ret = DP_GRPC_ERR_VNI_INIT4;
		goto handle_err;
	}

	rte_memcpy(port->iface.ul_ipv6, ul_addr6, sizeof(port->iface.ul_ipv6));
	port->iface.cfg.own_ip = request->ip4_addr;
	port->iface.cfg.ip_depth = DP_LPM_DHCP_IP_DEPTH;
	rte_memcpy(port->iface.cfg.dhcp_ipv6, request->ip6_addr, sizeof(port->iface.cfg.dhcp_ipv6));
	port->iface.cfg.ip6_depth = DP_LPM_DHCP_IP6_DEPTH;
	static_assert(sizeof(request->pxe_str) == sizeof(port->iface.cfg.pxe_str), "Incompatible interface PXE size");
	rte_memcpy(port->iface.cfg.pxe_str, request->pxe_str, sizeof(port->iface.cfg.pxe_str));
	port->iface.cfg.pxe_ip = request->ip4_pxe_addr;

	ret = dp_add_route(port, request->vni, 0, request->ip4_addr, NULL, 32);
	if (DP_FAILED(ret))
		goto iface_err;
	ret = dp_add_route6(port, request->vni, 0, request->ip6_addr, NULL, 128);
	if (DP_FAILED(ret))
		goto route_err;

	if (!port->is_pf)
		if (DP_FAILED(dp_port_meter_config(port, request->total_flow_rate_cap, request->public_flow_rate_cap))) {
			ret = DP_GRPC_ERR_PORT_METER;
			goto route6_err;
		}

	if (DP_FAILED(dp_start_port(port))) {
		ret = DP_GRPC_ERR_PORT_START;
		goto meter_err;
	}

	rte_memcpy(reply->ul_addr6, port->iface.ul_ipv6, sizeof(reply->ul_addr6));
	snprintf(reply->name, sizeof(reply->name), "%s", port->vf_name);
	return DP_GRPC_OK;

meter_err:
	dp_port_meter_config(port, 0, 0);
route6_err:
	dp_del_route6(port, request->vni, request->ip6_addr, 128);
route_err:
	dp_del_route(port, request->vni, request->ip4_addr, 32);
iface_err:
	dp_delete_iface(port);
handle_err:
	dp_unmap_iface_id(request->iface_id);
err_vnf:
	dp_del_vnf(ul_addr6);
err:
	return ret;
}

static int dp_process_delete_interface(struct dp_grpc_responder *responder)
{
	struct dpgrpc_iface_id *request = &responder->request.del_iface;

	struct dp_port *port;
	uint32_t ipv4;
	uint32_t vni;
	int ret = DP_GRPC_OK;

	port = dp_get_port_with_iface_id(request->iface_id);
	if (!port)
		return DP_GRPC_ERR_NOT_FOUND;

	ipv4 = port->iface.cfg.own_ip;
	vni = port->iface.vni;

	if (!port->is_pf)
		if (DP_FAILED(dp_port_meter_config(port, 0, 0)))
			ret = DP_GRPC_ERR_PORT_METER;

	dp_del_vnf(port->iface.ul_ipv6);
	if (DP_FAILED(dp_stop_port(port)))
		ret = DP_GRPC_ERR_PORT_STOP;
	// carry on with cleanup though
	dp_unmap_iface_id(request->iface_id);
	dp_delete_iface(port);
#ifdef ENABLE_VIRTSVC
	dp_virtsvc_del_iface(port->port_id);
#endif
	dp_remove_iface_flows(port->port_id, ipv4, vni);

	return ret;
}

static int dp_process_get_interface(struct dp_grpc_responder *responder)
{
	struct dpgrpc_iface_id *request = &responder->request.get_iface;
	struct dpgrpc_iface *reply = dp_grpc_single_reply(responder);

	struct dp_port *port;

	port = dp_get_port_with_iface_id(request->iface_id);
	if (!port)
		return DP_GRPC_ERR_NOT_FOUND;

	reply->ip4_addr = port->iface.cfg.own_ip;
	rte_memcpy(reply->ip6_addr, port->iface.cfg.dhcp_ipv6, sizeof(reply->ip6_addr));
	reply->vni = port->iface.vni;
	static_assert(sizeof(reply->iface_id) == sizeof(port->iface.id), "Incompatible VM ID size");
	rte_memcpy(reply->iface_id, port->iface.id, sizeof(reply->iface_id));
	static_assert(sizeof(reply->pci_name) == sizeof(port->dev_name), "Incompatible PCI name size");
	rte_memcpy(reply->pci_name, port->dev_name, sizeof(reply->pci_name));
	rte_memcpy(reply->ul_addr6, port->iface.ul_ipv6, sizeof(reply->ul_addr6));
	reply->total_flow_rate_cap = port->iface.total_flow_rate_cap;
	reply->public_flow_rate_cap = port->iface.public_flow_rate_cap;
	return DP_GRPC_OK;
}

static int dp_process_create_route(struct dp_grpc_responder *responder)
{
	struct dpgrpc_route *request = &responder->request.add_route;

	if (request->trgt_addr.ip_type != RTE_ETHER_TYPE_IPV6)
		return DP_GRPC_ERR_BAD_IPVER;

	if (request->pfx_addr.ip_type == RTE_ETHER_TYPE_IPV4) {
		return dp_add_route(dp_get_pf0(), request->vni, request->trgt_vni,
							request->pfx_addr.ipv4, request->trgt_addr.ipv6,
							request->pfx_length);
	} else if (request->pfx_addr.ip_type == RTE_ETHER_TYPE_IPV6) {
		return dp_add_route6(dp_get_pf0(), request->vni, request->trgt_vni,
							 request->pfx_addr.ipv6, request->trgt_addr.ipv6,
							 request->pfx_length);
	} else
		return DP_GRPC_ERR_BAD_IPVER;
}

static int dp_process_delete_route(struct dp_grpc_responder *responder)
{
	struct dpgrpc_route *request = &responder->request.del_route;

	if (request->pfx_addr.ip_type == RTE_ETHER_TYPE_IPV4) {
		return dp_del_route(dp_get_pf0(), request->vni, request->pfx_addr.ipv4, request->pfx_length);
	} else if (request->pfx_addr.ip_type == RTE_ETHER_TYPE_IPV6) {
		return dp_del_route6(dp_get_pf0(), request->vni, request->pfx_addr.ipv6, request->pfx_length);
	} else
		return DP_GRPC_ERR_BAD_IPVER;
}

static int dp_process_create_nat(struct dp_grpc_responder *responder)
{
	struct dpgrpc_nat *request = &responder->request.add_nat;
	struct dpgrpc_ul_addr *reply = dp_grpc_single_reply(responder);

	uint8_t ul_addr6[DP_VNF_IPV6_ADDR_SIZE];
	struct dp_ip_address pfx_ip = {
		.ip_type = request->addr.ip_type
	};
	struct dp_port *port;
	uint32_t iface_ip, iface_vni;
	int ret;

	port = dp_get_port_with_iface_id(request->iface_id);
	if (!port) {
		ret = DP_GRPC_ERR_NO_VM;
		goto err;
	}

	if (request->addr.ip_type == RTE_ETHER_TYPE_IPV4) {
		iface_ip = port->iface.cfg.own_ip;
		iface_vni = port->iface.vni;
		if (DP_FAILED(dp_create_vnf_route(ul_addr6, DP_VNF_TYPE_NAT, iface_vni, port, &pfx_ip, 0))) {
			ret = DP_GRPC_ERR_VNF_INSERT;
			goto err;
		}
		ret = dp_set_iface_nat_ip(iface_ip, request->addr.ipv4, iface_vni,
										request->min_port, request->max_port,
										ul_addr6);
		if (DP_FAILED(ret))
			goto err_vnf;

		ret = dp_set_dnat_ip(request->addr.ipv4, 0, iface_vni);
		if (DP_FAILED(ret) && ret != DP_GRPC_ERR_DNAT_EXISTS)
			goto err_dnat;
		port->iface.nat_ip = request->addr.ipv4;
		port->iface.nat_port_range[0] = request->min_port;
		port->iface.nat_port_range[1] = request->max_port;
		rte_memcpy(reply->addr6, ul_addr6, sizeof(reply->addr6));
	} else {
		ret = DP_GRPC_ERR_BAD_IPVER;
		goto err;
	}
	return DP_GRPC_OK;

err_dnat:
	dp_del_iface_nat_ip(iface_ip, iface_vni);
err_vnf:
	dp_del_vnf(ul_addr6);
err:
	return ret;

}

static int dp_process_delete_nat(struct dp_grpc_responder *responder)
{
	struct dpgrpc_iface_id *request = &responder->request.del_nat;
	struct dpgrpc_vip *reply = dp_grpc_single_reply(responder);

	struct dp_port *port;
	struct snat_data *s_data;
	uint32_t iface_ip, iface_vni;

	port = dp_get_port_with_iface_id(request->iface_id);
	if (!port)
		return DP_GRPC_ERR_NO_VM;

	iface_ip = port->iface.cfg.own_ip;
	iface_vni = port->iface.vni;

	s_data = dp_get_iface_snat_data(iface_ip, iface_vni);
	if (!s_data || !s_data->nat_ip)
		return DP_GRPC_ERR_SNAT_NO_DATA;

	dp_del_vnf(s_data->ul_nat_ip6);

	reply->addr.ip_type = RTE_ETHER_TYPE_IPV4;
	reply->addr.ipv4 = s_data->nat_ip;
	dp_del_vip_from_dnat(s_data->nat_ip, iface_vni);
	port->iface.nat_ip = 0;
	port->iface.nat_port_range[0] = 0;
	port->iface.nat_port_range[1] = 0;
	dp_remove_nat_flows(port->port_id, DP_FLOW_NAT_TYPE_NETWORK_LOCAL);
	return dp_del_iface_nat_ip(iface_ip, iface_vni);
}

static int dp_process_get_nat(struct dp_grpc_responder *responder)
{
	struct dpgrpc_iface_id *request = &responder->request.get_nat;
	struct dpgrpc_nat *reply = dp_grpc_single_reply(responder);

	struct dp_port *port;
	struct snat_data *s_data;

	port = dp_get_port_with_iface_id(request->iface_id);
	if (!port)
		return DP_GRPC_ERR_NO_VM;

	s_data = dp_get_iface_snat_data(port->iface.cfg.own_ip, port->iface.vni);
	if (!s_data || !s_data->nat_ip)
		return DP_GRPC_ERR_SNAT_NO_DATA;

	reply->addr.ip_type = RTE_ETHER_TYPE_IPV4;
	reply->addr.ipv4 = s_data->nat_ip;
	reply->min_port = s_data->nat_port_range[0];
	reply->max_port = s_data->nat_port_range[1];
	rte_memcpy(reply->ul_addr6, s_data->ul_nat_ip6, sizeof(reply->ul_addr6));
	return DP_GRPC_OK;
}

static int dp_process_create_neighnat(struct dp_grpc_responder *responder)
{
	struct dpgrpc_nat *request = &responder->request.add_nat;
	int ret;

	if (request->addr.ip_type == RTE_ETHER_TYPE_IPV4) {
		ret = dp_add_network_nat_entry(request->addr.ipv4, NULL,
									   request->vni,
									   request->min_port,
									   request->max_port,
									   request->neigh_addr6);
		if (DP_FAILED(ret))
			return ret;

		ret = dp_set_dnat_ip(request->addr.ipv4, 0, request->vni);
		if (DP_FAILED(ret) && ret != DP_GRPC_ERR_DNAT_EXISTS) {
			dp_del_network_nat_entry(request->addr.ipv4, NULL,
									 request->vni,
									 request->min_port,
									 request->max_port);
			return ret;
		}
	} else
		return DP_GRPC_ERR_BAD_IPVER;

	return DP_GRPC_OK;
}

static int dp_process_delete_neighnat(struct dp_grpc_responder *responder)
{
	struct dpgrpc_nat *request = &responder->request.del_neighnat;
	int ret = DP_GRPC_OK;

	if (request->addr.ip_type == RTE_ETHER_TYPE_IPV4) {
		ret = dp_del_network_nat_entry(request->addr.ipv4, NULL,
									   request->vni,
									   request->min_port,
									   request->max_port);
		if (ret == DP_GRPC_ERR_NOT_FOUND)
			return ret;

		dp_del_vip_from_dnat(request->addr.ipv4, request->vni);
		dp_remove_neighnat_flows(request->addr.ipv4, request->vni, request->min_port, request->max_port);
	} else
		return DP_GRPC_ERR_BAD_IPVER;

	return ret;

}

static int dp_process_list_interfaces(struct dp_grpc_responder *responder)
{
	struct dpgrpc_iface *reply;
	const struct dp_ports *ports = dp_get_ports();

	dp_grpc_set_multireply(responder, sizeof(*reply));

	DP_FOREACH_PORT(ports, port) {
		if (!port->iface.ready)
			continue;

		reply = dp_grpc_add_reply(responder);
		if (!reply)
			return DP_GRPC_ERR_OUT_OF_MEMORY;

		reply->ip4_addr = port->iface.cfg.own_ip;
		rte_memcpy(reply->ip6_addr, port->iface.cfg.dhcp_ipv6, sizeof(reply->ip6_addr));
		reply->vni = port->iface.vni;
		static_assert(sizeof(reply->iface_id) == sizeof(port->iface.id), "Incompatible VM ID size");
		rte_memcpy(reply->iface_id, port->iface.id, sizeof(reply->iface_id));
		static_assert(sizeof(reply->pci_name) == sizeof(port->dev_name), "Incompatible PCI name size");
		rte_memcpy(reply->pci_name, port->dev_name, sizeof(reply->pci_name));
		rte_memcpy(reply->ul_addr6, port->iface.ul_ipv6, sizeof(reply->ul_addr6));
		reply->total_flow_rate_cap = port->iface.total_flow_rate_cap;
		reply->public_flow_rate_cap = port->iface.public_flow_rate_cap;
	}

	return DP_GRPC_OK;
}

static int dp_process_list_routes(struct dp_grpc_responder *responder)
{
	return dp_list_routes(dp_get_pf0(), responder->request.list_route.vni,
						  DP_LIST_EXT_ROUTES, responder);
}

static int dp_process_list_lbtargets(struct dp_grpc_responder *responder)
{
	return dp_get_lb_back_ips(responder->request.list_lbtrgt.lb_id, responder);
}

static int dp_process_list_fwrules(struct dp_grpc_responder *responder)
{
	struct dp_port *port;

	port = dp_get_port_with_iface_id(responder->request.list_fwrule.iface_id);
	if (!port)
		return DP_GRPC_ERR_NO_VM;

	return dp_list_firewall_rules(port, responder);
}

static int dp_process_list_lbprefixes(struct dp_grpc_responder *responder)
{
	struct dp_port *port;

	port = dp_get_port_with_iface_id(responder->request.list_lbpfx.iface_id);
	if (!port)
		return DP_GRPC_ERR_NO_VM;

	return dp_list_vnf_alias_prefixes(port->port_id, DP_VNF_TYPE_LB_ALIAS_PFX, responder);
}

static int dp_process_list_prefixes(struct dp_grpc_responder *responder)
{
	struct dp_port *port;

	port = dp_get_port_with_iface_id(responder->request.list_pfx.iface_id);
	if (!port)
		return DP_GRPC_ERR_NO_VM;

	return dp_list_vnf_alias_prefixes(port->port_id, DP_VNF_TYPE_ALIAS_PFX, responder);
}

static int dp_process_list_localnats(struct dp_grpc_responder *responder)
{
	struct dp_ip_address *request = &responder->request.list_localnat;

	if (request->ip_type == RTE_ETHER_TYPE_IPV4)
		return dp_list_nat_local_entries(request->ipv4, responder);
	else
		return DP_GRPC_ERR_BAD_IPVER;
}

static int dp_process_list_neighnats(struct dp_grpc_responder *responder)
{
	struct dp_ip_address *request = &responder->request.list_neighnat;

	if (request->ip_type == RTE_ETHER_TYPE_IPV4)
		return dp_list_nat_neigh_entries(request->ipv4, responder);
	else
		return DP_GRPC_ERR_BAD_IPVER;
}


static int dp_process_get_version(struct dp_grpc_responder *responder)
{
	struct dpgrpc_versions *reply = dp_grpc_single_reply(responder);

	// currently, ignore client's versions and only report what the service supports
	static_assert(sizeof(reply->proto) >= sizeof(DP_SERVICE_VERSION),
				  "gRPC protocol's proto version field is too large");
	rte_memcpy(reply->proto, DP_SERVICE_VERSION, sizeof(DP_SERVICE_VERSION));
	static_assert(sizeof(reply->app) >= sizeof(DP_SERVICE_VERSION),
				  "gRPC protocol's app version field is too large");
	rte_memcpy(reply->app, DP_SERVICE_VERSION, sizeof(DP_SERVICE_VERSION));
	return DP_GRPC_OK;
}

static int dp_process_capture_start(struct dp_grpc_responder *responder)
{
	struct dpgrpc_capture *request = &responder->request.capture_start;
	struct dp_port *port = NULL;
	int status = DP_GRPC_OK;

	if (!dp_conf_is_offload_enabled())
		return DP_GRPC_ERR_NOT_ACTIVE;

	if (dp_is_capture_enabled())
		return DP_GRPC_ERR_ALREADY_ACTIVE;

	dp_set_capture_hdr_config(request->dst_addr6, request->udp_src_port, request->udp_dst_port);

	for (int i = 0; i < request->interface_count; ++i) {
		switch (request->interfaces[i].type) {
		case DP_CAPTURE_IFACE_TYPE_SINGLE_VF:
			port = dp_get_port_with_iface_id(request->interfaces[i].spec.iface_id);
			break;
		case DP_CAPTURE_IFACE_TYPE_SINGLE_PF:
			port = dp_get_port_by_pf_index(request->interfaces[i].spec.pf_index);
			break;
		}

		if (!port) {
			DPS_LOG_WARNING("Got invalid port when initializing capturing", DP_LOG_PORT(port));
			status = DP_GRPC_ERR_NOT_FOUND;
			break;
		}

		status = dp_enable_pkt_capture(port);
		if (DP_FAILED(status)) // stop continuing to turn on offload capture on other interfaces, if capturing init failed on any port. abort and rollback.
			break;
	}

	// try to turn off capture on all interfaces if any of them failed to turn on
	if (DP_FAILED(status)) {
		if (DP_FAILED(dp_disable_pkt_capture_on_all_ifaces()))
			status = DP_GRPC_ERR_ROLLBACK;
	} else
		dp_set_capture_enabled(true);

	return status;
}

static int dp_process_capture_stop(struct dp_grpc_responder *responder)
{
	struct dpgrpc_capture_stop	*reply = dp_grpc_single_reply(responder);
	int ret;

	if (!dp_is_capture_enabled())
		return DP_GRPC_ERR_NOT_ACTIVE;

	ret = dp_disable_pkt_capture_on_all_ifaces();
	if (DP_FAILED(ret)) {
		DPS_LOG_ERR("Failed to stop packet capture on all interfaces"); // it is problematic that we cannot rollback here
		return ret;
	}

	reply->port_cnt = (uint16_t)ret;
	dp_set_capture_enabled(false);
	return DP_GRPC_OK;
}

static int dp_process_capture_status(struct dp_grpc_responder *responder)
{
	struct dpgrpc_capture *reply = dp_grpc_single_reply(responder);
	const struct dp_ports *ports = dp_get_ports();
	const struct dp_capture_hdr_config *capture_hdr_config = dp_get_capture_hdr_config();
	uint8_t count = 0;

	if (!dp_is_capture_enabled()) {
		memset(reply, 0, sizeof(*reply));
		// this includes setting reply->is_active to false
		return DP_GRPC_OK;
	}

	DP_FOREACH_PORT(ports, port) {
		if (!port->allocated || !port->captured)
			continue;

		// this should never happen, but just in case
		static_assert(DP_CAPTURE_MAX_PORT_NUM < UINT8_MAX,
					  "Possible number of captured ports is too big");
		if (count >= DP_CAPTURE_MAX_PORT_NUM) {
			DPS_LOG_ERR("Unexpected number of interfaces are being captured",
						DP_LOG_VALUE(count), DP_LOG_MAX(DP_CAPTURE_MAX_PORT_NUM));
			return DP_GRPC_ERR_LIMIT_REACHED;
		}

		if (port->is_pf) {
			reply->interfaces[count].type = DP_CAPTURE_IFACE_TYPE_SINGLE_PF;
			reply->interfaces[count].spec.pf_index = port == dp_get_pf0() ? 0 : 1;
		} else {
			reply->interfaces[count].type = DP_CAPTURE_IFACE_TYPE_SINGLE_VF;
			static_assert(sizeof(reply->interfaces[count].spec.iface_id) == sizeof(port->iface.id),
						  "Invalid size for captured interface id");
			rte_memcpy(reply->interfaces[count].spec.iface_id, port->iface.id, sizeof(port->iface.id));
		}
		count++;
	}

	rte_memcpy(reply->dst_addr6, capture_hdr_config->capture_node_ipv6_addr, sizeof(reply->dst_addr6));
	reply->udp_src_port = capture_hdr_config->capture_udp_src_port;
	reply->udp_dst_port = capture_hdr_config->capture_udp_dst_port;
	reply->interface_count = count;
	reply->is_active = true;

	return DP_GRPC_OK;
}


void dp_process_request(struct rte_mbuf *m)
{
	struct dp_grpc_responder responder;
	enum dpgrpc_request_type request_type;
	int ret;

	request_type = dp_grpc_init_responder(&responder, m);

	switch (request_type) {
	case DP_REQ_TYPE_Initialize:
		ret = dp_process_initialize(&responder);
		break;
	case DP_REQ_TYPE_GetVersion:
		ret = dp_process_get_version(&responder);
		break;
	case DP_REQ_TYPE_CreateInterface:
		ret = dp_process_create_interface(&responder);
		break;
	case DP_REQ_TYPE_DeleteInterface:
		ret = dp_process_delete_interface(&responder);
		break;
	case DP_REQ_TYPE_GetInterface:
		ret = dp_process_get_interface(&responder);
		break;
	case DP_REQ_TYPE_ListInterfaces:
		ret = dp_process_list_interfaces(&responder);
		break;
	case DP_REQ_TYPE_CreatePrefix:
		ret = dp_process_create_prefix(&responder);
		break;
	case DP_REQ_TYPE_DeletePrefix:
		ret = dp_process_delete_prefix(&responder);
		break;
	case DP_REQ_TYPE_ListPrefixes:
		ret = dp_process_list_prefixes(&responder);
		break;
	case DP_REQ_TYPE_CreateRoute:
		ret = dp_process_create_route(&responder);
		break;
	case DP_REQ_TYPE_DeleteRoute:
		ret = dp_process_delete_route(&responder);
		break;
	case DP_REQ_TYPE_ListRoutes:
		ret = dp_process_list_routes(&responder);
		break;
	case DP_REQ_TYPE_CreateVip:
		ret = dp_process_create_vip(&responder);
		break;
	case DP_REQ_TYPE_DeleteVip:
		ret = dp_process_delete_vip(&responder);
		break;
	case DP_REQ_TYPE_GetVip:
		ret = dp_process_get_vip(&responder);
		break;
	case DP_REQ_TYPE_CreateNat:
		ret = dp_process_create_nat(&responder);
		break;
	case DP_REQ_TYPE_DeleteNat:
		ret = dp_process_delete_nat(&responder);
		break;
	case DP_REQ_TYPE_GetNat:
		ret = dp_process_get_nat(&responder);
		break;
	case DP_REQ_TYPE_CreateNeighborNat:
		ret = dp_process_create_neighnat(&responder);
		break;
	case DP_REQ_TYPE_DeleteNeighborNat:
		ret = dp_process_delete_neighnat(&responder);
		break;
	case DP_REQ_TYPE_ListLocalNats:
		ret = dp_process_list_localnats(&responder);
		break;
	case DP_REQ_TYPE_ListNeighborNats:
		ret = dp_process_list_neighnats(&responder);
		break;
	case DP_REQ_TYPE_CreateLoadBalancer:
		ret = dp_process_create_lb(&responder);
		break;
	case DP_REQ_TYPE_DeleteLoadBalancer:
		ret = dp_process_delete_lb(&responder);
		break;
	case DP_REQ_TYPE_GetLoadBalancer:
		ret = dp_process_get_lb(&responder);
		break;
	case DP_REQ_TYPE_CreateLoadBalancerTarget:
		ret = dp_process_create_lbtarget(&responder);
		break;
	case DP_REQ_TYPE_DeleteLoadBalancerTarget:
		ret = dp_process_delete_lbtarget(&responder);
		break;
	case DP_REQ_TYPE_ListLoadBalancerTargets:
		ret = dp_process_list_lbtargets(&responder);
		break;
	case DP_REQ_TYPE_CreateLoadBalancerPrefix:
		ret = dp_process_create_lbprefix(&responder);
		break;
	case DP_REQ_TYPE_DeleteLoadBalancerPrefix:
		ret = dp_process_delete_lbprefix(&responder);
		break;
	case DP_REQ_TYPE_ListLoadBalancerPrefixes:
		ret = dp_process_list_lbprefixes(&responder);
		break;
	case DP_REQ_TYPE_CreateFirewallRule:
		ret = dp_process_create_fwrule(&responder);
		break;
	case DP_REQ_TYPE_DeleteFirewallRule:
		ret = dp_process_delete_fwrule(&responder);
		break;
	case DP_REQ_TYPE_GetFirewallRule:
		ret = dp_process_get_fwrule(&responder);
		break;
	case DP_REQ_TYPE_ListFirewallRules:
		ret = dp_process_list_fwrules(&responder);
		break;
	case DP_REQ_TYPE_CheckVniInUse:
		ret = dp_process_check_vniinuse(&responder);
		break;
	case DP_REQ_TYPE_ResetVni:
		ret = dp_process_reset_vni(&responder);
		break;
	case DP_REQ_TYPE_CaptureStart:
		ret = dp_process_capture_start(&responder);
		break;
	case DP_REQ_TYPE_CaptureStop:
		ret = dp_process_capture_stop(&responder);
		break;
	case DP_REQ_TYPE_CaptureStatus:
		ret = dp_process_capture_status(&responder);
		break;
	// DP_REQ_TYPE_CheckInitialized is handled by the gRPC thread
	default:
		ret = DP_GRPC_ERR_BAD_REQUEST;
		break;
	}

	if (DP_FAILED(ret)) {
		// as gRPC errors are explicitly defined due to API reasons
		// extract the proper value from the standard (negative) retvals
		ret = dp_errcode_to_grpc_errcode(ret);
		DPGRPC_LOG_WARNING("Failed request", DP_LOG_GRPCREQUEST(responder.request.type), DP_LOG_GRPCRET(ret));
	}

	dp_grpc_send_response(&responder, ret);
}
