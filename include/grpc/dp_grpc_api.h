// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#ifndef __DP_GRPC_API_H__
#define __DP_GRPC_API_H__

#include <stdint.h>
#include <rte_common.h>
#include "dp_firewall.h"
#include "dp_iface.h"
#include "dp_util.h"
#include "monitoring/dp_monitoring.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DP_GRPC_VERSION_MAX_LEN	64

// Names have mixed-case due to autogeneration macros in dp_async_grpc.h
enum dpgrpc_request_type {
	DP_REQ_TYPE_NONE,
	DP_REQ_TYPE_Initialize,
	DP_REQ_TYPE_CheckInitialized,
	DP_REQ_TYPE_GetVersion,
	DP_REQ_TYPE_CreateInterface,
	DP_REQ_TYPE_DeleteInterface,
	DP_REQ_TYPE_GetInterface,
	DP_REQ_TYPE_ListInterfaces,
	DP_REQ_TYPE_CreatePrefix,
	DP_REQ_TYPE_DeletePrefix,
	DP_REQ_TYPE_ListPrefixes,
	DP_REQ_TYPE_CreateRoute,
	DP_REQ_TYPE_DeleteRoute,
	DP_REQ_TYPE_ListRoutes,
	DP_REQ_TYPE_CreateVip,
	DP_REQ_TYPE_DeleteVip,
	DP_REQ_TYPE_GetVip,
	DP_REQ_TYPE_CreateNat,
	DP_REQ_TYPE_DeleteNat,
	DP_REQ_TYPE_GetNat,
	DP_REQ_TYPE_CreateNeighborNat,
	DP_REQ_TYPE_DeleteNeighborNat,
	DP_REQ_TYPE_ListLocalNats,
	DP_REQ_TYPE_ListNeighborNats,
	DP_REQ_TYPE_CreateLoadBalancer,
	DP_REQ_TYPE_DeleteLoadBalancer,
	DP_REQ_TYPE_GetLoadBalancer,
	DP_REQ_TYPE_ListLoadBalancers,
	DP_REQ_TYPE_CreateLoadBalancerTarget,
	DP_REQ_TYPE_DeleteLoadBalancerTarget,
	DP_REQ_TYPE_ListLoadBalancerTargets,
	DP_REQ_TYPE_CreateLoadBalancerPrefix,
	DP_REQ_TYPE_DeleteLoadBalancerPrefix,
	DP_REQ_TYPE_ListLoadBalancerPrefixes,
	DP_REQ_TYPE_CreateFirewallRule,
	DP_REQ_TYPE_DeleteFirewallRule,
	DP_REQ_TYPE_GetFirewallRule,
	DP_REQ_TYPE_ListFirewallRules,
	DP_REQ_TYPE_CheckVniInUse,
	DP_REQ_TYPE_ResetVni,
	DP_REQ_TYPE_CaptureStart,
	DP_REQ_TYPE_CaptureStop,
	DP_REQ_TYPE_CaptureStatus,
};

// in sync with dpdk proto!
enum dpgrpc_vni_type {
	DP_VNI_IPV4,
	DP_VNI_IPV6,
	DP_VNI_BOTH,
};

enum dpgrpc_capture_iface_type {
	DP_CAPTURE_IFACE_TYPE_SINGLE_PF,
	DP_CAPTURE_IFACE_TYPE_SINGLE_VF,
};

struct dpgrpc_iface {
	char					iface_id[DP_IFACE_ID_MAX_LEN] __rte_aligned(4);
	uint32_t				ip4_addr;
	union dp_ipv6			ip6_addr;
	uint32_t				vni;
	struct dp_ip_address	pxe_addr;							// request (create) only
	char					pxe_str[DP_IFACE_PXE_MAX_LEN];		// request (create) only
	char					hostname[DP_IFACE_HOSTNAME_MAX_LEN];
	char					pci_name[RTE_ETH_NAME_MAX_LEN];
	union dp_ipv6			ul_addr6;
	uint64_t				total_flow_rate_cap;
	uint64_t				public_flow_rate_cap;
};

struct dpgrpc_iface_id {
	char 					iface_id[DP_IFACE_ID_MAX_LEN] __rte_aligned(4);
};

struct dpgrpc_prefix {
	char					iface_id[DP_IFACE_ID_MAX_LEN] __rte_aligned(4);
	struct dp_ip_address	addr;
	uint8_t					length;
	union dp_ipv6			ul_addr6;
};

struct dpgrpc_route {
	struct dp_ip_address	pfx_addr;
	uint8_t					pfx_length;
	uint32_t				vni;
	struct dp_ip_address	trgt_addr;
	uint32_t				trgt_vni;
};

struct dpgrpc_vip {
	char					iface_id[DP_IFACE_ID_MAX_LEN] __rte_aligned(4);
	struct dp_ip_address	addr;
	union dp_ipv6			ul_addr6;
};

struct dpgrpc_nat {
	char					iface_id[DP_IFACE_ID_MAX_LEN] __rte_aligned(4);	// local only
	struct dp_ip_address	addr;
	uint16_t				min_port;
	uint16_t				max_port;
	uint32_t				vni;							// neighnat or reply only
	union dp_ipv6			neigh_addr6;					// neighnat only
	union dp_ipv6			ul_addr6;
	struct dp_ip_address	natted_ip;						// list localnats reply only
};

struct dpgrpc_lb_port {
	uint8_t					protocol;
	uint16_t				port;
};

struct dpgrpc_lb {
	char					lb_id[DP_LB_ID_MAX_LEN];		// request only
	struct dp_ip_address	addr;
	uint32_t				vni;
	struct dpgrpc_lb_port	lbports[DP_LB_MAX_PORTS];
	union dp_ipv6			ul_addr6;
};

struct dpgrpc_lb_id {
	char					lb_id[DP_LB_ID_MAX_LEN];
};

struct dpgrpc_lb_target {
	char					lb_id[DP_LB_ID_MAX_LEN];
	struct dp_ip_address	addr;
};

struct dpgrpc_fwrule {
	char					iface_id[DP_IFACE_ID_MAX_LEN] __rte_aligned(4);
	struct dp_fwall_rule	rule;
};

struct dpgrpc_fwrule_id {
	char					iface_id[DP_IFACE_ID_MAX_LEN] __rte_aligned(4);
	char					rule_id[DP_FIREWALL_ID_MAX_LEN];
};

struct dpgrpc_vni {
	uint32_t				vni;
	enum dpgrpc_vni_type	type;
};

struct dpgrpc_versions {
	char					name[DP_GRPC_VERSION_MAX_LEN];	// request only
	char					proto[DP_GRPC_VERSION_MAX_LEN];
	char					app[DP_GRPC_VERSION_MAX_LEN];
};

struct dpgrpc_capture_interface {
	union {
		char		iface_id[DP_IFACE_ID_MAX_LEN] __rte_aligned(4);
		uint8_t		pf_index;
	} spec;
	enum dpgrpc_capture_iface_type	type;
};

struct dpgrpc_capture {
	union dp_ipv6	dst_addr6;
	uint8_t			interface_count;
	uint16_t		udp_src_port;
	uint16_t		udp_dst_port;
	struct dpgrpc_capture_interface interfaces[DP_CAPTURE_MAX_PORT_NUM];
	bool			is_active;
};

struct dpgrpc_capture_stop {
	uint16_t		port_cnt;
};

struct dpgrpc_request {
	enum dpgrpc_request_type	type;
	union {
		struct dpgrpc_iface		add_iface;
		struct dpgrpc_iface_id	del_iface;
		struct dpgrpc_iface_id	get_iface;
		struct dpgrpc_prefix	add_pfx;
		struct dpgrpc_prefix	del_pfx;
		struct dpgrpc_iface_id	list_pfx;
		struct dpgrpc_route		add_route;
		struct dpgrpc_route		del_route;
		struct dpgrpc_vni		list_route;
		struct dpgrpc_vip		add_vip;
		struct dpgrpc_iface_id	del_vip;
		struct dpgrpc_iface_id	get_vip;
		struct dpgrpc_nat		add_nat;
		struct dpgrpc_iface_id	del_nat;
		struct dpgrpc_iface_id	get_nat;
		struct dpgrpc_nat		add_neighnat;
		struct dpgrpc_nat		del_neighnat;
		struct dp_ip_address	list_localnat;
		struct dp_ip_address	list_neighnat;
		struct dpgrpc_lb		add_lb;
		struct dpgrpc_lb_id		del_lb;
		struct dpgrpc_lb_id		get_lb;
		struct dpgrpc_lb_target	add_lbtrgt;
		struct dpgrpc_lb_target	del_lbtrgt;
		struct dpgrpc_lb_id		list_lbtrgt;
		struct dpgrpc_prefix	add_lbpfx;
		struct dpgrpc_prefix	del_lbpfx;
		struct dpgrpc_iface_id	list_lbpfx;
		struct dpgrpc_fwrule	add_fwrule;
		struct dpgrpc_fwrule_id	del_fwrule;
		struct dpgrpc_fwrule_id	get_fwrule;
		struct dpgrpc_iface_id	list_fwrule;
		struct dpgrpc_vni		vni_in_use;
		struct dpgrpc_vni		vni_reset;
		struct dpgrpc_versions	get_version;
		struct dpgrpc_capture	capture_start;
	};
};

struct dpgrpc_vf_pci {
	char			name[RTE_ETH_NAME_MAX_LEN];
	union dp_ipv6	ul_addr6;
};

struct dpgrpc_ul_addr {
	union dp_ipv6	addr6;
};

struct dpgrpc_fwrule_info {
	struct dp_fwall_rule	rule;
};

struct dpgrpc_vni_in_use {
	uint8_t			in_use;
};

struct dpgrpc_reply {
	enum dpgrpc_request_type		type;			// copied enum dpgrpc_request_type
	bool							is_chained;
	uint16_t						msg_count;
	uint32_t						err_code;
	union {
		uint8_t						messages[0];	// used for multiresponse mode
		struct dpgrpc_ul_addr		ul_addr;
		struct dpgrpc_iface			iface;
		struct dpgrpc_vf_pci		vf_pci;
		struct dpgrpc_route			route;
		struct dpgrpc_vip			vip;
		struct dpgrpc_nat			nat;
		struct dpgrpc_lb			lb;
		struct dpgrpc_fwrule_info	fwrule;
		struct dpgrpc_vni_in_use	vni_in_use;
		struct dpgrpc_versions		versions;
		struct dpgrpc_capture_stop	capture_stop;
		struct dpgrpc_capture		capture_get;
	};
};

#ifdef __cplusplus
}
#endif
#endif
