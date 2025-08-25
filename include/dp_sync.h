// SPDX-FileCopyrightText: 2025 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#ifndef __INCLUDE_DP_SYNC_H__
#define __INCLUDE_DP_SYNC_H__

#include "dp_nat.h"

// RFC 7042: 0x88B5  IEEE Std 802      - Local Experimental Ethertype
#define DP_SYNC_ETHERTYPE 0x88B5

// NOTE: there will be no endianness protection; both ends should be running on the same machine

// no versioning, if really needed, just create another message type
struct dp_sync_hdr {
	uint8_t msg_type;
} __rte_packed;

// active -> backup: incremental change to NAT tables
#define DP_SYNC_MSG_NAT_CREATE		1
struct dp_sync_msg_nat_create {
	struct netnat_portmap_key portmap_key;
	struct netnat_portoverload_tbl_key portoverload_key;
	uint16_t created_port_id;
	uint16_t icmp_type_src;
	rte_be16_t icmp_err_ip_cksum;
} __rte_packed;

#define DP_SYNC_MSG_NAT_DELETE		2
struct dp_sync_msg_nat_delete {
	struct netnat_portmap_key portmap_key;
	struct netnat_portoverload_tbl_key portoverload_key;
} __rte_packed;

#define DP_SYNC_MSG_VIRTSVC_CONN	3
struct dp_sync_msg_virtsvc_conn {
	rte_be32_t virtual_addr;
	rte_be16_t virtual_port;
	uint16_t conn_port;
	rte_be32_t vf_ip;
	rte_be16_t vf_l4_port;
	uint16_t vf_port_id;
	uint8_t proto;
} __rte_packed;

#define DP_SYNC_MSG_PORT_MAC		4
struct dp_sync_msg_port_mac {
	uint16_t port_id;
	struct rte_ether_addr mac;
}; // cannot use __rte_packed due to rte_ether_addr requirements (no big deal, this message is rarely sent)

// backup -> active: please re-send all tables
#define DP_SYNC_MSG_REQUEST_DUMP	5


int dp_sync_send_nat_create(const struct netnat_portmap_key *portmap_key,
							const struct netnat_portoverload_tbl_key *portoverload_key,
							uint16_t created_port_id,
							uint16_t icmp_type_src, rte_be16_t icmp_err_ip_cksum);

int dp_sync_send_nat_delete(const struct netnat_portmap_key *portmap_key,
							const struct netnat_portoverload_tbl_key *portoverload_key);

#ifdef ENABLE_VIRTSVC
int dp_sync_send_virtsvc_conn(const struct dp_virtsvc *virtsvc, uint16_t conn_port,
							  rte_be32_t vf_ip, rte_be16_t vf_l4_port, uint16_t vf_port_id);
#endif

int dp_sync_send_mac(uint16_t port_id, const struct rte_ether_addr *mac);

int dp_sync_send_request_dump(void);

#endif
