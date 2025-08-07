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

// TODO virtsvc create+delete
// backup -> active: please re-send all tables
#define DP_SYNC_MSG_REQUEST_DUMP	5
// TODO multi-entry structure for performance?


int dp_sync_send_nat_create(const struct netnat_portmap_key *portmap_key,
							const struct netnat_portoverload_tbl_key *portoverload_key,
							uint16_t created_port_id,
							uint16_t icmp_type_src, rte_be16_t icmp_err_ip_cksum);

int dp_sync_send_nat_delete(const struct netnat_portmap_key *portmap_key,
							const struct netnat_portoverload_tbl_key *portoverload_key);

int dp_sync_send_request_dump(void);

#endif
