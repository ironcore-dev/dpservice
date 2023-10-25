#ifndef __DP_GRPC_API_H__
#define __DP_GRPC_API_H__

#include <stdint.h>
#include "dp_util.h"
#include "dp_firewall.h"
#include "monitoring/dp_monitoring.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DP_VNF_IPV6_ADDR_SIZE	16

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
	char					iface_id[VM_IFACE_ID_MAX_LEN];
	uint32_t				ip4_addr;
	uint8_t					ip6_addr[DP_VNF_IPV6_ADDR_SIZE];
	uint32_t				vni;
	uint32_t				ip4_pxe_addr;						// request (create) only
	char					pxe_str[VM_MACHINE_PXE_MAX_LEN];	// request (create) only
	char					pci_name[RTE_ETH_NAME_MAX_LEN];
	uint8_t					ul_addr6[DP_VNF_IPV6_ADDR_SIZE];	// reply only
};

struct dpgrpc_iface_id {
	char 					iface_id[VM_IFACE_ID_MAX_LEN];
};

struct dpgrpc_address {
	uint32_t				ip_type;
	union {
		// TODO(plague): this is sometimes network, sometimes host byte order! (needs PR)
		uint32_t			ipv4;
		uint8_t				ipv6[DP_VNF_IPV6_ADDR_SIZE];
	};
};

struct dpgrpc_prefix {
	struct dpgrpc_address	addr;
	uint32_t				length;
	char					iface_id[VM_IFACE_ID_MAX_LEN];
};

struct dpgrpc_route {
	struct dpgrpc_address	pfx_addr;
	uint32_t				pfx_length;
	uint32_t				vni;
	struct dpgrpc_address	trgt_addr;
	uint32_t				trgt_vni;
};

struct dpgrpc_vip {
	struct dpgrpc_address	addr;
	char					iface_id[VM_IFACE_ID_MAX_LEN];
	uint8_t					ul_addr6[DP_VNF_IPV6_ADDR_SIZE];	// reply only
};

struct dpgrpc_nat {
	char					iface_id[VM_IFACE_ID_MAX_LEN];		// local only
	struct dpgrpc_address	addr;
	uint16_t				min_port;
	uint16_t				max_port;
	uint32_t				vni;								// neighnat or reply only
	uint8_t					neigh_addr6[DP_VNF_IPV6_ADDR_SIZE];	// neighnat only
	uint8_t					ul_addr6[DP_VNF_IPV6_ADDR_SIZE];	// reply only
};

struct dpgrpc_lb_port {
	uint8_t					protocol;
	uint16_t				port;
};

struct dpgrpc_lb {
	char					lb_id[DP_LB_ID_MAX_LEN];			// request only
	struct dpgrpc_address	addr;
	uint32_t				vni;
	struct dpgrpc_lb_port	lbports[DP_LB_MAX_PORTS];
	uint8_t					ul_addr6[DP_VNF_IPV6_ADDR_SIZE];	// reply only
};

struct dpgrpc_lb_id {
	char					lb_id[DP_LB_ID_MAX_LEN];
};

struct dpgrpc_lb_target {
	char					lb_id[DP_LB_ID_MAX_LEN];
	struct dpgrpc_address	addr;
};

struct dpgrpc_fwrule {
	char					iface_id[VM_IFACE_ID_MAX_LEN];
	struct dp_fwall_rule	rule;
};

struct dpgrpc_fwrule_id {
	char					iface_id[VM_IFACE_ID_MAX_LEN];
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
	enum dpgrpc_capture_iface_type	type;
	union {
		char	iface_id[VM_IFACE_ID_MAX_LEN];
		uint8_t pf_index;
	} interface_info;
};

struct dpgrpc_capture_config {
	uint8_t			dst_addr6[DP_VNF_IPV6_ADDR_SIZE];
	uint8_t			filled_interface_info_count;
	uint32_t		udp_src_port;
	uint32_t		udp_dst_port;
	struct dpgrpc_capture_interface interfaces[DP_CAPTURE_MAX_PORT_NUM];
};

struct dpgrpc_capture_stat {
	uint8_t							status;
	struct dpgrpc_capture_interface interface;
};

struct dpgrpc_capture_stop {
	uint16_t						port_cnt;
};

struct dpgrpc_request {
	uint16_t 					type;  // enum dpgrpc_request_type
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
		struct dpgrpc_address	list_localnat;
		struct dpgrpc_address	list_neighnat;
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
		struct dpgrpc_capture_config	start_capture;
	};
};

struct dpgrpc_vf_pci {
	char		name[RTE_ETH_NAME_MAX_LEN];
	uint8_t		ul_addr6[DP_VNF_IPV6_ADDR_SIZE];
};

struct dpgrpc_ul_addr {
	uint8_t		addr6[DP_VNF_IPV6_ADDR_SIZE];
};

struct dpgrpc_fwrule_info {
	struct dp_fwall_rule rule;
};

struct dpgrpc_vni_in_use {
	uint8_t		in_use;
};

struct dpgrpc_reply {
	uint8_t		type;  // copied enum dpgrpc_request_type
	uint8_t		is_chained;
	uint16_t	msg_count;
	uint32_t	err_code;
	union {
		uint8_t						messages[0];  // used for multiresponse mode
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
		struct dpgrpc_capture_stat 	capture_stat;
		struct dpgrpc_capture_stop	capture_stop;
	};
};

#ifdef __cplusplus
}
#endif
#endif
