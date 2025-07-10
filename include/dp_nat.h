// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#ifndef __INCLUDE_DP_NAT_H__
#define __INCLUDE_DP_NAT_H__


#include <sys/queue.h>
#include <rte_common.h>
#include <rte_mbuf.h>
#include "dp_flow.h"
#include "dp_ipaddr.h"
#include "grpc/dp_grpc_responder.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DP_NAT_DNAT_TABLE_NAME "dnat_table"
#define DP_NAT_SNAT_TABLE_NAME "snat_table"
#define DP_NAT_PORTMAP_TABLE_NAME "nat_portmap_table"
#define DP_NAT_PORTOVERLOAD_TABLE_NAME "nat_portoverload_table"

#define DP_NETWORK_NAT_ALL_VNI		0

struct nat_key {
	uint32_t	ip;
	uint32_t	vni;
} __rte_packed;

struct nat_entry {
	uint32_t		nat_ip;
	uint16_t		port_range[2];
	uint32_t		vni;
	union dp_ipv6	dst_ipv6;
	// checkpatch silencing comment
	TAILQ_ENTRY(nat_entry) entries;
};

struct snat_data {
	uint32_t		vip_ip;
	uint32_t		nat_ip;
	uint16_t		nat_port_range[2];
	union dp_ipv6	ul_vip_ip6;
	union dp_ipv6	ul_nat_ip6;
	uint64_t		log_timestamp;
};

struct dnat_data {
	uint32_t	dnat_ip;
};

struct netnat_portmap_key {
	uint32_t				vni;
	struct dp_ip_address	src_ip;
	uint16_t				iface_src_port;
} __rte_packed;

struct netnat_portmap_data {
	uint32_t	nat_ip;
	uint16_t	nat_port;
	uint16_t	flow_cnt;
};

struct netnat_portoverload_tbl_key {
	uint32_t nat_ip;
	uint16_t nat_port;
	uint32_t dst_ip;
	uint16_t dst_port;
	uint8_t	l4_type;
} __rte_packed;

struct nat_check_result {
	bool	is_vip_natted;
	bool	is_network_natted;
};

int dp_nat_init(int socket_id);
void dp_nat_free(void);

int dp_set_iface_vip_ip(uint32_t iface_ip, uint32_t vip_ip, uint32_t vni,
						const union dp_ipv6 *ul_ipv6);
int dp_del_iface_vip_ip(uint32_t iface_ip, uint32_t vni);

uint32_t dp_get_iface_nat_ip(uint32_t iface_ip, uint32_t vni);
int dp_set_iface_nat_ip(uint32_t iface_ip, uint32_t nat_ip, uint32_t vni, uint16_t min_port, uint16_t max_port,
						const union dp_ipv6 *ul_ipv6);
int dp_del_iface_nat_ip(uint32_t iface_ip, uint32_t vni);

int dp_del_dnat_ip(uint32_t d_ip, uint32_t vni);
struct dnat_data *dp_get_dnat_data(uint32_t d_ip, uint32_t vni);
int dp_set_dnat_ip(uint32_t d_ip, uint32_t dnat_ip, uint32_t vni);

void dp_nat_chg_ip(struct dp_flow *df, struct rte_ipv4_hdr *ipv4_hdr,
				   struct rte_mbuf *m);

int dp_nat_chg_ipv6_to_ipv4_hdr(struct dp_flow *df, struct rte_mbuf *m, uint32_t nat_ip, rte_be32_t *dest_ip /* out */);
int dp_nat_chg_ipv4_to_ipv6_hdr(struct dp_flow *df, struct rte_mbuf *m, const union dp_ipv6 *ipv6_addr);

void dp_del_vip_from_dnat(uint32_t d_ip, uint32_t vni);

int dp_add_neighnat_entry(uint32_t nat_ip,  uint32_t vni, uint16_t min_port, uint16_t max_port,
						  const union dp_ipv6 *ul_ipv6);

int dp_del_neighnat_entry(uint32_t nat_ip, uint32_t vni, uint16_t min_port, uint16_t max_port);

int dp_allocate_network_snat_port(struct snat_data *snat_data, struct dp_flow *df, struct dp_port *port);
int dp_allocate_sync_snat_port(const struct netnat_portmap_key *portmap_key,
							   struct netnat_portoverload_tbl_key *portoverload_key);
const union dp_ipv6 *dp_lookup_neighnat_underlay_ip(struct dp_flow *df);
int dp_remove_network_snat_port(const struct flow_value *cntrack);
int dp_remove_sync_snat_port(const struct netnat_portmap_key *portmap_key,
							 const struct netnat_portoverload_tbl_key *portoverload_key);
int dp_create_sync_snat_flows(void);

int dp_list_nat_local_entries(uint32_t nat_ip, struct dp_grpc_responder *responder);
int dp_list_nat_neigh_entries(uint32_t nat_ip, struct dp_grpc_responder *responder);
struct snat_data *dp_get_iface_snat_data(uint32_t iface_ip, uint32_t vni);
void dp_del_all_neigh_nat_entries_in_vni(uint32_t vni);

#ifdef __cplusplus
}
#endif
#endif
