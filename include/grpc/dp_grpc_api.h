#ifndef __DP_GRPC_API_H__
#define __DP_GRPC_API_H__

#include <stdint.h>
#include "dp_util.h"
#include "dp_firewall.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DP_VNF_IPV6_ADDR_SIZE	16

// TODO shouldn't all of this be do_grpc though? 'struct dp_lb' seems not ideal for the future
// TODO OOOOOOR just make them dp_req_* and dp_rep_* !!!

enum dp_request_type {
	DP_REQ_TYPE_NONE,
	DP_REQ_TYPE_INIT,
	DP_REQ_TYPE_INITIALIZED,
	DP_REQ_TYPE_ADD_INTERFACE,
	DP_REQ_TYPE_DEL_INTERFACE,
	DP_REQ_TYPE_GET_INTERFACE,
	DP_REQ_TYPE_LIST_INTERFACES,
	DP_REQ_TYPE_ADD_PREFIX,
	DP_REQ_TYPE_DEL_PREFIX,
	DP_REQ_TYPE_LIST_PREFIXES,
	DP_REQ_TYPE_ADD_ROUTE,
	DP_REQ_TYPE_DEL_ROUTE,
	DP_REQ_TYPE_LIST_ROUTES,
	DP_REQ_TYPE_ADD_VIP,
	DP_REQ_TYPE_DEL_VIP,
	DP_REQ_TYPE_GET_VIP,
	DP_REQ_TYPE_ADD_NAT,
	DP_REQ_TYPE_DEL_NAT,
	DP_REQ_TYPE_GET_NAT,
	DP_REQ_TYPE_ADD_NEIGHNAT,
	DP_REQ_TYPE_DEL_NEIGHNAT,
	DP_REQ_TYPE_GET_NATINFO,
	DP_REQ_TYPE_ADD_LB,
	DP_REQ_TYPE_DEL_LB,
	DP_REQ_TYPE_GET_LB,
	DP_REQ_TYPE_ADD_LBTARGET,
	DP_REQ_TYPE_DEL_LBTARGET,
	DP_REQ_TYPE_LIST_LBTARGETS,
	DP_REQ_TYPE_ADD_LBPREFIX,
	DP_REQ_TYPE_DEL_LBPREFIX,
	DP_REQ_TYPE_LIST_LBPREFIXES,
	DP_REQ_TYPE_ADD_FWRULE,
	DP_REQ_TYPE_DEL_FWRULE,
	DP_REQ_TYPE_GET_FWRULE,
	DP_REQ_TYPE_LIST_FWRULES,
	DP_REQ_TYPE_VNI_INUSE,
	DP_REQ_TYPE_VNI_RESET,
};

// in sync with dpdk proto!
enum dp_natinfo_type {
	DP_NATINFO_TYPE_ZERO,
	DP_NATINFO_TYPE_LOCAL,
	DP_NATINFO_TYPE_NEIGHBOR,
};

// in sync with dpdk proto!
enum dp_vni_type {
	DP_VNI_IPV4,
	DP_VNI_IPV6,
	DP_VNI_BOTH,
};

struct dp_iface {
	char			iface_id[VM_IFACE_ID_MAX_LEN];
	uint32_t		ip4_addr;
	uint8_t			ip6_addr[DP_VNF_IPV6_ADDR_SIZE];
	uint32_t		vni;
	uint32_t		ip4_pxe_addr;						// request (add) only
	char			pxe_str[VM_MACHINE_PXE_MAX_LEN];	// request (add) only
	char			pci_name[RTE_ETH_NAME_MAX_LEN];
	uint8_t			ul_addr6[DP_VNF_IPV6_ADDR_SIZE];	// reply only
};

struct dp_iface_id {
	char 			iface_id[VM_IFACE_ID_MAX_LEN];
};

struct dp_prefix {
	uint32_t		ip_type;
	union {
		uint32_t	addr;
		uint8_t		addr6[DP_VNF_IPV6_ADDR_SIZE];
	};
	uint32_t		length;
	char			iface_id[VM_IFACE_ID_MAX_LEN];
};

struct dp_route {
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

struct dp_vip {
	uint32_t		ip_type;
	union {
		uint32_t	addr;
		uint8_t		addr6[DP_VNF_IPV6_ADDR_SIZE];
	};
	char			iface_id[VM_IFACE_ID_MAX_LEN];
	uint8_t			ul_addr6[DP_VNF_IPV6_ADDR_SIZE];	// reply only
};

struct dp_nat {
	char			iface_id[VM_IFACE_ID_MAX_LEN];		// local only
	uint32_t		ip_type;
	union {
		uint32_t	addr;
		uint8_t		addr6[DP_VNF_IPV6_ADDR_SIZE];
	};
	uint16_t		min_port;
	uint16_t		max_port;
	uint32_t		neigh_vni;							// neighnat only
	uint8_t			neigh_addr6[DP_VNF_IPV6_ADDR_SIZE];	// neighnat only
	uint8_t			type;  // enum dp_natinfo_type		// reply only
	uint8_t			ul_addr6[DP_VNF_IPV6_ADDR_SIZE];	// reply only
};

struct dp_nat_id {
	uint8_t			type;  // enum dp_natinfo_type
	uint32_t		ip_type;
	union {
		uint32_t	addr;
		uint8_t		addr6[DP_VNF_IPV6_ADDR_SIZE];
	};
};

struct dp_lb_port {
	uint16_t protocol;
	uint16_t port;
};

struct dp_lb {
	char				lb_id[DP_LB_ID_MAX_LEN];		// request only
	uint32_t			ip_type;
	union {
		uint32_t		addr;
		uint8_t			addr6[DP_VNF_IPV6_ADDR_SIZE];
	};
	uint32_t			vni;
	struct dp_lb_port	lbports[DP_LB_MAX_PORTS];
	uint8_t				ul_addr6[DP_VNF_IPV6_ADDR_SIZE];	// reply only
};

struct dp_lb_id {
	char			lb_id[DP_LB_ID_MAX_LEN];
};

struct dp_lb_target {
	char			lb_id[DP_LB_ID_MAX_LEN];
	uint32_t		ip_type;
	union {
		uint32_t	addr;
		uint8_t		addr6[DP_VNF_IPV6_ADDR_SIZE];
	};
};

struct dp_fwrule {
	char					iface_id[VM_IFACE_ID_MAX_LEN];
	struct dp_fwall_rule	rule;
};

struct dp_fwrule_id {
	char			iface_id[VM_IFACE_ID_MAX_LEN];
	char			rule_id[DP_FIREWALL_ID_MAX_LEN];
};

struct dp_vni {
	uint32_t			vni;
	enum dp_vni_type	type;
};

struct dp_request {
	uint16_t 		type;  // enum dp_request_type
	union {
		struct dp_iface		add_iface;
		struct dp_iface_id	del_iface;
		struct dp_iface_id	get_iface;
		struct dp_prefix	add_pfx;
		struct dp_prefix	del_pfx;
		struct dp_iface_id	list_pfx;
		struct dp_route		add_route;
		struct dp_route		del_route;
		struct dp_vni		list_route;
		struct dp_vip		add_vip;
		struct dp_iface_id	del_vip;
		struct dp_iface_id	get_vip;
		struct dp_nat		add_nat;
		struct dp_iface_id	del_nat;
		struct dp_iface_id	get_nat;
		struct dp_nat		add_neighnat;
		struct dp_nat		del_neighnat;
		struct dp_nat_id	list_nat;
		struct dp_lb		add_lb;
		struct dp_lb_id		del_lb;
		struct dp_lb_id		get_lb;
		struct dp_lb_target	add_lbtrgt;
		struct dp_lb_target	del_lbtrgt;
		struct dp_lb_id		list_lbtrgt;
		struct dp_prefix	add_lbpfx;
		struct dp_prefix	del_lbpfx;
		struct dp_iface_id	list_lbpfx;
		struct dp_fwrule	add_fwrule;
		struct dp_fwrule_id	del_fwrule;
		struct dp_fwrule_id	get_fwrule;
		struct dp_iface_id	list_fwrule;
		struct dp_vni		vni_in_use;
		struct dp_vni		vni_reset;
	};
};

struct dp_vf_pci {
	char		name[RTE_ETH_NAME_MAX_LEN];
	uint32_t	domain;
	uint32_t	bus;
	uint32_t	slot;
	uint32_t	function;
	uint8_t		ul_addr6[DP_VNF_IPV6_ADDR_SIZE];
};

struct dp_ul_addr {
	uint8_t		addr6[DP_VNF_IPV6_ADDR_SIZE];
};

struct dp_vni_in_use {
	uint8_t		in_use;
};

struct dp_reply {
	uint8_t		type;
	uint8_t		is_chained;
	uint16_t	msg_count;
	uint32_t	err_code;
	union {
		uint8_t					messages[0];  // used for multiresponse mode
		struct dp_ul_addr		ul_addr;
		struct dp_iface			iface;
		struct dp_vf_pci		vf_pci;
		struct dp_route			route;
		struct dp_vip			vip;
		struct dp_nat			nat;
		struct dp_lb			lb;
		struct dp_fwall_rule	fwall_rule;
		struct dp_vni_in_use	vni_in_use;
	};
};

#ifdef __cplusplus
}
#endif
#endif
