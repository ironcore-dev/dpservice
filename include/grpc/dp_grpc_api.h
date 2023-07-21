#ifndef __DP_GRPC_API_H__
#define __DP_GRPC_API_H__

#include <stdint.h>
#include "dp_util.h"
#include "dp_firewall.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DP_VNF_IPV6_ADDR_SIZE	16

#define DP_GRPC_VERSION_MAX_LEN	64

enum dpgrpc_request_type {
	DP_REQ_TYPE_NONE,
	DP_REQ_TYPE_INITIALIZE,
	DP_REQ_TYPE_CHECK_INITIALIZED,
	DP_REQ_TYPE_GET_VERSION,
	DP_REQ_TYPE_CREATE_INTERFACE,
	DP_REQ_TYPE_DELETE_INTERFACE,
	DP_REQ_TYPE_GET_INTERFACE,
	DP_REQ_TYPE_LIST_INTERFACES,
	DP_REQ_TYPE_CREATE_PREFIX,
	DP_REQ_TYPE_DELETE_PREFIX,
	DP_REQ_TYPE_LIST_PREFIXES,
	DP_REQ_TYPE_CREATE_ROUTE,
	DP_REQ_TYPE_DELETE_ROUTE,
	DP_REQ_TYPE_LIST_ROUTES,
	DP_REQ_TYPE_CREATE_VIP,
	DP_REQ_TYPE_DELETE_VIP,
	DP_REQ_TYPE_GET_VIP,
	DP_REQ_TYPE_CREATE_NAT,
	DP_REQ_TYPE_DELETE_NAT,
	DP_REQ_TYPE_GET_NAT,
	DP_REQ_TYPE_CREATE_NEIGHNAT,
	DP_REQ_TYPE_DELETE_NEIGHNAT,
	DP_REQ_TYPE_LIST_LOCALNATS,
	DP_REQ_TYPE_LIST_NEIGHNATS,
	DP_REQ_TYPE_CREATE_LB,
	DP_REQ_TYPE_DELETE_LB,
	DP_REQ_TYPE_GET_LB,
	DP_REQ_TYPE_CREATE_LBTARGET,
	DP_REQ_TYPE_DELETE_LBTARGET,
	DP_REQ_TYPE_LIST_LBTARGETS,
	DP_REQ_TYPE_CREATE_LBPREFIX,
	DP_REQ_TYPE_DELETE_LBPREFIX,
	DP_REQ_TYPE_LIST_LBPREFIXES,
	DP_REQ_TYPE_CREATE_FWRULE,
	DP_REQ_TYPE_DELETE_FWRULE,
	DP_REQ_TYPE_GET_FWRULE,
	DP_REQ_TYPE_LIST_FWRULES,
	DP_REQ_TYPE_CHECK_VNIINUSE,
	DP_REQ_TYPE_RESET_VNI,
};

// in sync with dpdk proto!
enum dpgrpc_vni_type {
	DP_VNI_IPV4,
	DP_VNI_IPV6,
	DP_VNI_BOTH,
};

struct dpgrpc_iface {
	char			iface_id[VM_IFACE_ID_MAX_LEN];
	uint32_t		ip4_addr;
	uint8_t			ip6_addr[DP_VNF_IPV6_ADDR_SIZE];
	uint32_t		vni;
	uint32_t		ip4_pxe_addr;						// request (add) only
	char			pxe_str[VM_MACHINE_PXE_MAX_LEN];	// request (add) only
	char			pci_name[RTE_ETH_NAME_MAX_LEN];
	uint8_t			ul_addr6[DP_VNF_IPV6_ADDR_SIZE];	// reply only
};

struct dpgrpc_iface_id {
	char 			iface_id[VM_IFACE_ID_MAX_LEN];
};

struct dpgrpc_prefix {
	uint32_t		ip_type;
	union {
		uint32_t	addr;
		uint8_t		addr6[DP_VNF_IPV6_ADDR_SIZE];
	};
	uint32_t		length;
	char			iface_id[VM_IFACE_ID_MAX_LEN];
};

struct dpgrpc_route {
	uint32_t		pfx_ip_type;
	union {
		uint32_t	pfx_addr;
		uint8_t		pfx_addr6[DP_VNF_IPV6_ADDR_SIZE];
	};
	uint32_t		pfx_length;
	uint32_t		vni;
	uint32_t		trgt_ip_type;
	union {
		uint32_t	trgt_addr;
		uint8_t		trgt_addr6[DP_VNF_IPV6_ADDR_SIZE];
	};
	uint32_t		trgt_vni;
};

struct dpgrpc_vip {
	uint32_t		ip_type;
	union {
		uint32_t	addr;
		uint8_t		addr6[DP_VNF_IPV6_ADDR_SIZE];
	};
	char			iface_id[VM_IFACE_ID_MAX_LEN];
	uint8_t			ul_addr6[DP_VNF_IPV6_ADDR_SIZE];	// reply only
};

struct dpgrpc_nat {
	char			iface_id[VM_IFACE_ID_MAX_LEN];		// local only
	uint32_t		ip_type;
	union {
		uint32_t	addr;
		uint8_t		addr6[DP_VNF_IPV6_ADDR_SIZE];
	};
	uint16_t		min_port;
	uint16_t		max_port;
	uint32_t		vni;								// neighnat or reply only
	uint8_t			neigh_addr6[DP_VNF_IPV6_ADDR_SIZE];	// neighnat only
	uint8_t			ul_addr6[DP_VNF_IPV6_ADDR_SIZE];	// reply only
};

struct dpgrpc_nat_id {
	uint32_t		ip_type;
	union {
		uint32_t	addr;
		uint8_t		addr6[DP_VNF_IPV6_ADDR_SIZE];
	};
};

struct dpgrpc_lb_port {
	uint16_t		protocol;
	uint16_t		port;
};

struct dpgrpc_lb {
	char					lb_id[DP_LB_ID_MAX_LEN];			// request only
	uint32_t				ip_type;
	union {
		uint32_t			addr;
		uint8_t				addr6[DP_VNF_IPV6_ADDR_SIZE];
	};
	uint32_t				vni;
	struct dpgrpc_lb_port	lbports[DP_LB_MAX_PORTS];
	uint8_t					ul_addr6[DP_VNF_IPV6_ADDR_SIZE];	// reply only
};

struct dpgrpc_lb_id {
	char			lb_id[DP_LB_ID_MAX_LEN];
};

struct dpgrpc_lb_target {
	char			lb_id[DP_LB_ID_MAX_LEN];
	uint32_t		ip_type;
	union {
		uint32_t	addr;
		uint8_t		addr6[DP_VNF_IPV6_ADDR_SIZE];
	};
};

struct dpgrpc_fwrule {
	char					iface_id[VM_IFACE_ID_MAX_LEN];
	struct dp_fwall_rule	rule;
};

struct dpgrpc_fwrule_id {
	char			iface_id[VM_IFACE_ID_MAX_LEN];
	char			rule_id[DP_FIREWALL_ID_MAX_LEN];
};

struct dpgrpc_vni {
	uint32_t				vni;
	enum dpgrpc_vni_type	type;
};

struct dpgrpc_versions {
	char			name[DP_GRPC_VERSION_MAX_LEN];	// request only
	char			proto[DP_GRPC_VERSION_MAX_LEN];
	char			app[DP_GRPC_VERSION_MAX_LEN];
};

struct dpgrpc_request {
	uint16_t 		type;  // enum dpgrpc_request_type
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
		struct dpgrpc_nat_id	list_localnat;
		struct dpgrpc_nat_id	list_neighnat;
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
	};
};

struct dpgrpc_vf_pci {
	char		name[RTE_ETH_NAME_MAX_LEN];
	uint32_t	domain;
	uint32_t	bus;
	uint32_t	slot;
	uint32_t	function;
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
	};
};

#ifdef __cplusplus
}
#endif
#endif
