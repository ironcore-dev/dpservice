// SPDX-FileCopyrightText: 2025 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#ifndef __INCLUDE_DP_SYNC_H__
#define __INCLUDE_DP_SYNC_H__

#include "dp_nat.h"

// RFC 7042: 0x88B5  IEEE Std 802      - Local Experimental Ethertype
#define DP_SYNC_ETHERTYPE 0x88B5

// NOTE: there will be no endianness protection; both ends should be running on the same machine

// no versioning, version is only needed to be sent one at the start of communication
struct dp_sync_hdr {
	uint8_t msg_type;
} __rte_packed;

#define DP_SYNC_MSG_REQUEST_UPDATES 0
// standby dpservice sends this to the active one and requests updates to NAT tables
// the active dpservice must send them in requested version of the protocol
// to do a rolling update, do two updates:
//  - first add support for new protocol, but do not request it
//  - after both dpservices support the new protocol, update again and request it
struct dp_sync_msg_request_updates {
	uint8_t version;
} __rte_packed;

#define DP_SYNC_MSG_NAT_CREATE 10
#define DP_SYNC_MSG_NAT_DELETE 11
struct dp_sync_msg_nat_keys {
	struct netnat_portmap_key portmap_key;
	struct netnat_portoverload_tbl_key portoverload_key;
} __rte_packed;


int dp_sync_send_nat_create(const struct netnat_portmap_key *portmap_key,
							const struct netnat_portoverload_tbl_key *portoverload_key);

int dp_sync_send_nat_delete(const struct netnat_portmap_key *portmap_key,
							const struct netnat_portoverload_tbl_key *portoverload_key);

#endif
