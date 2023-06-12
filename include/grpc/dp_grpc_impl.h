#ifndef __INCLUDE_DP_GRPC_IMPL_H__
#define __INCLUDE_DP_GRPC_IMPL_H__

#include <stdint.h>
#include <rte_mbuf.h>
#include <rte_ethdev.h>
#include <net/if.h>
#include "dp_util.h"
#include "dp_firewall.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DP_VNF_IPV6_ADDR_SIZE	16

typedef enum {
	DP_REQ_TYPE_NONE,
	DP_REQ_TYPE_ADDLBVIP,
	DP_REQ_TYPE_DELLBVIP,
	DP_REQ_TYPE_LISTLBBACKENDS,
	DP_REQ_TYPE_ADDVIP,
	DP_REQ_TYPE_DELVIP,
	DP_REQ_TYPE_GETVIP,
	DP_REQ_TYPE_ADD_FWALL_RULE,
	DP_REQ_TYPE_DEL_FWALL_RULE,
	DP_REQ_TYPE_GET_FWALL_RULE,
	DP_REQ_TYPE_LIST_FWALL_RULES,
	DP_REQ_TYPE_ADDMACHINE,
	DP_REQ_TYPE_DELMACHINE,
	DP_REQ_TYPE_GETMACHINE,
	DP_REQ_TYPE_ADDROUTE,
	DP_REQ_TYPE_DELROUTE,
	DP_REQ_TYPE_LISTROUTE,
	DP_REQ_TYPE_LISTMACHINE,
	DP_REQ_TYPE_ADDPREFIX,
	DP_REQ_TYPE_DELPREFIX,
	DP_REQ_TYPE_LISTPREFIX,
	DP_REQ_TYPE_ADDLBPREFIX,
	DP_REQ_TYPE_DELLBPREFIX,
	DP_REQ_TYPE_LISTLBPREFIX,
	DP_REQ_TYPE_INITIALIZED,
	DP_REQ_TYPE_INIT,
	DP_REQ_TYPE_CREATELB,
	DP_REQ_TYPE_GETLB,
	DP_REQ_TYPE_DELLB,
	DP_REQ_TYPE_ADD_NATVIP,
	DP_REQ_TYPE_GET_NATENTRY,
	DP_REQ_TYPE_GET_NATVIP,
	DP_REQ_TYPE_DEL_NATVIP,
	DP_REQ_TYPE_ADD_NEIGH_NAT,
	DP_REQ_TYPE_DEL_NEIGH_NAT,
	DP_REQ_TYPE_IS_VNI_IN_USE,
	DP_REQ_TYPE_VNI_RESET,
} dp_req_type;

typedef enum {
	DP_NETNAT_INFO_ZERO,
	DP_NETNAT_INFO_TYPE_LOCAL,
	DP_NETNAT_INFO_TYPE_NEIGHBOR,
} dp_netnat_info_type;

typedef enum {
	DP_VNI_IPV4,
	DP_VNI_IPV6,
	DP_VNI_BOTH,
} dp_vni_use_type;

typedef struct dp_com_head {
	uint8_t com_type;
	uint8_t is_chained;
	uint16_t msg_count;
	uint32_t err_code;
} dp_com_head;

typedef struct dp_lb_port {
	uint16_t protocol;
	uint16_t port;
} dp_lb_port;

typedef struct dp_vip {
	uint32_t	ip_type;
	union {
		uint32_t	vip_addr;
		uint8_t		vip_addr6[DP_VNF_IPV6_ADDR_SIZE];
	} vip;
	char		machine_id[VM_MACHINE_ID_STR_LEN];
	uint8_t		ul_addr6[DP_VNF_IPV6_ADDR_SIZE];
} dp_vip;

typedef struct dp_fw_rule {
	char			machine_id[VM_MACHINE_ID_STR_LEN];
	struct dp_fwall_rule	rule;
} dp_fw_rule;

typedef struct dp_vni_use {
	uint32_t		vni;
	dp_vni_use_type	type;
	uint32_t		in_use;
} dp_vni_use;

typedef struct dp_lb {
	uint32_t	ip_type;
	union {
		uint32_t	vip_addr;
		uint8_t		vip_addr6[DP_VNF_IPV6_ADDR_SIZE];
	} vip;
	uint32_t	vni;
	uint8_t		ul_addr6[DP_VNF_IPV6_ADDR_SIZE];
	struct dp_lb_port lbports[DP_LB_PORT_SIZE];
} dp_lb;

typedef struct dp_pfx {
	uint32_t pfx_ip_type;
	union {
		uint32_t	pfx_addr;
		uint8_t		pfx_addr6[DP_VNF_IPV6_ADDR_SIZE];
	} pfx_ip;
	uint32_t	pfx_length;
	uint8_t		pfx_ul_addr6[DP_VNF_IPV6_ADDR_SIZE];
	char machine_id[VM_MACHINE_ID_STR_LEN];
} dp_pfx;

typedef struct dp_lp_qry_lb {
	char	lb_id[DP_LB_ID_SIZE];
} dp_lp_qry_lb;

typedef struct dp_lb_vip {
	char		lb_id[DP_LB_ID_SIZE];
	uint32_t	ip_type;
	union {
		uint32_t	back_addr;
		uint8_t		back_addr6[DP_VNF_IPV6_ADDR_SIZE];
	} back;
} dp_lb_vip;

typedef struct dp_addmachine {
	uint32_t	ip4_addr;
	uint8_t		ip6_addr6[DP_VNF_IPV6_ADDR_SIZE];
	char		machine_id[VM_MACHINE_ID_STR_LEN];
	uint32_t	vni;
	uint32_t	ip4_pxe_addr;
	char		pxe_str[VM_MACHINE_PXE_STR_LEN];
	char		name[RTE_ETH_NAME_MAX_LEN];
} dp_addmachine;

typedef struct dp_delmachine {
	char		machine_id[VM_MACHINE_ID_STR_LEN];
} dp_delmachine;

typedef struct dp_getmachine {
	char		machine_id[VM_MACHINE_ID_STR_LEN];
} dp_getmachine;

typedef struct dp_delvip {
	char		machine_id[VM_MACHINE_ID_STR_LEN];
} dp_delvip;

typedef struct dp_getvip {
	char		machine_id[VM_MACHINE_ID_STR_LEN];
} dp_getvip;

typedef struct dp_getpfx {
	char		machine_id[VM_MACHINE_ID_STR_LEN];
} dp_getpfx;

typedef struct dp_add_lb {
	char		lb_id[DP_LB_ID_SIZE];
	uint32_t	ip_type;
	union {
		uint32_t	vip_addr;
		uint8_t		vip_addr6[DP_VNF_IPV6_ADDR_SIZE];
	} vip;
	uint32_t	vni;
	struct dp_lb_port lbports[DP_LB_PORT_SIZE];
} dp_add_lb;

typedef struct dp_list_lb {
	char	lb_id[DP_LB_ID_SIZE];
} dp_list_lb;

typedef struct dp_del_lb {
	char	lb_id[DP_LB_ID_SIZE];
} dp_del_lb;

typedef struct dp_addroute {
	uint32_t	pfx_ip_type;
	union {
		uint32_t	addr;
		uint8_t		addr6[DP_VNF_IPV6_ADDR_SIZE];
	} pfx_ip;
	uint32_t	pfx_length;
	uint32_t	trgt_hop_ip_type;
	union {
		uint32_t	addr;
		uint8_t		addr6[DP_VNF_IPV6_ADDR_SIZE];
	} trgt_ip;
	uint32_t	vni;
	uint32_t	trgt_vni;
	uint32_t	weight;
} dp_route;

typedef struct dp_nat_vip {
	dp_netnat_info_type	type;
	uint32_t ip_type;
	union {
		uint32_t	vip_addr;
		uint8_t		vip_addr6[DP_VNF_IPV6_ADDR_SIZE];
	} vip;
	char machine_id[VM_MACHINE_ID_STR_LEN];
	uint32_t port_range[2];
	uint8_t		route[DP_VNF_IPV6_ADDR_SIZE];
	uint32_t	vni;
} dp_net_nat;

typedef struct dp_request {
	dp_com_head com_head;
	union {
		dp_pfx			add_pfx;
		dp_vip			add_vip;
		dp_add_lb		add_lb;
		dp_list_lb		get_lb;
		dp_del_lb		del_lb;
		dp_lb_vip		add_lb_vip;
		dp_lb_vip		del_lb_vip;
		dp_net_nat		add_nat_vip;
		dp_net_nat		get_nat_entry;
		dp_net_nat		del_nat_vip;
		dp_net_nat		add_nat_neigh;
		dp_net_nat		del_nat_neigh;
		dp_lp_qry_lb	qry_lb_vip;
		dp_addmachine	add_machine;
		dp_delmachine	del_machine;
		dp_getmachine	get_machine;
		dp_delvip		del_vip;
		dp_getvip		get_vip;
		dp_route		route;
		dp_getpfx		get_pfx;
		dp_fw_rule		fw_rule;
		dp_vni_use		vni_in_use;
	};
} dp_request;

typedef struct dp_vf_pci {
	char		name[RTE_ETH_NAME_MAX_LEN];
	uint32_t	domain;
	uint32_t	bus;
	uint32_t	slot;
	uint32_t	function;
	uint8_t		ul_addr6[DP_VNF_IPV6_ADDR_SIZE];
} dp_vf_pci;

typedef struct dp_vm_info {
	uint32_t	ip_addr;
	uint8_t		ip6_addr[DP_VNF_IPV6_ADDR_SIZE];
	uint8_t		machine_id[VM_MACHINE_ID_STR_LEN];
	uint32_t	vni;
	char		pci_name[RTE_ETH_NAME_MAX_LEN];
	uint8_t		ul_addr6[DP_VNF_IPV6_ADDR_SIZE];
} dp_vm_info;

typedef struct dp_lb_backip {
	union {
		uint32_t	addr;
		uint8_t		addr6[DP_VNF_IPV6_ADDR_SIZE];
	} b_ip;
} dp_lb_backip;

typedef struct dp_nat_entry {
	union {
		uint32_t	addr;
		uint8_t		addr6[DP_VNF_IPV6_ADDR_SIZE];
	} m_ip;
	uint32_t	min_port;
	uint32_t	max_port;
	uint8_t		entry_type; // DP_NETNAT_INFO_TYPE_LOCAL or DP_NETNAT_INFO_TYPE_NEIGHBOR
	uint8_t		underlay_route[DP_VNF_IPV6_ADDR_SIZE];
} dp_nat_entry;

typedef struct dp_reply {
	dp_com_head com_head;
	union {
		dp_vip			get_vip;
		dp_lb			get_lb;
		dp_vf_pci		vf_pci;
		dp_vm_info		vm_info;
		dp_route		route;
		dp_lb_backip	back_ip;
		dp_nat_entry	nat_entry;
		uint8_t			ul_addr6[DP_VNF_IPV6_ADDR_SIZE];
		dp_fw_rule		fw_rule;
		dp_vni_use		vni_in_use;
	};
} dp_reply;

int dp_send_to_worker(dp_request *req);
int dp_recv_from_worker(dp_reply *rep);
int dp_recv_from_worker_with_mbuf(struct rte_mbuf **m);
int dp_process_request(struct rte_mbuf *m);
void dp_fill_head(dp_com_head* head, uint16_t type,
				  uint8_t is_chained, uint8_t count);
struct rte_mbuf* dp_add_mbuf_to_grpc_arr(struct rte_mbuf* m_curr,
										 struct rte_mbuf *rep_arr[],
										 int8_t *size);
uint16_t dp_first_mbuf_to_grpc_arr(struct rte_mbuf* m_curr,
								   struct rte_mbuf *rep_arr[],
								   int8_t *idx, uint16_t size);
void dp_last_mbuf_from_grpc_arr(struct rte_mbuf* m_curr,
								struct rte_mbuf *rep_arr[]);

#ifdef __cplusplus
}
#endif
#endif