// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#ifndef __INCLUDE_DP_VIRTSVC_H__
#define __INCLUDE_DP_VIRTSVC_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <rte_byteorder.h>
#include <rte_flow.h>
#include <rte_hash.h>
#include <rte_telemetry.h>
#include "dp_ipaddr.h"
#include "dpdk_layer.h"

// limit number of services to one byte due to various implementation reasons
#define DP_VIRTSVC_MAX 256

#define DP_NB_SYSTEM_PORTS 1024
#define DP_VIRTSVC_PORTCOUNT (UINT16_MAX+1 - DP_NB_SYSTEM_PORTS)

enum dp_virtsvc_conn_state {
	DP_VIRTSVC_CONN_TRANSIENT,
	DP_VIRTSVC_CONN_TRANSIENT_SYN,
	DP_VIRTSVC_CONN_TRANSIENT_SYNACK,
	DP_VIRTSVC_CONN_ESTABLISHED
};

struct dp_virtsvc_conn {
	uint64_t last_pkt_timestamp;
	// if pressed for space, this can be recovered from vf_port_id, but it's relatively costly
	rte_be32_t vf_ip;
	rte_be16_t vf_l4_port;
	uint16_t vf_port_id;
	// due to alignment (and direct use of enum), this causes 8B increase of size
	// if pressed for space, this can be lowered
	enum dp_virtsvc_conn_state state;
};

struct dp_virtsvc {
	rte_be32_t		virtual_addr;
	union dp_ipv6	service_addr;
	rte_be16_t		virtual_port;
	rte_be16_t		service_port;
	uint8_t			proto;
	uint16_t		last_assigned_port;
	union dp_ipv6	ul_addr;
	struct rte_hash	*open_ports;
	struct dp_virtsvc_conn connections[DP_VIRTSVC_PORTCOUNT];
};

struct dp_virtsvc_lookup_entry {
	struct dp_virtsvc *virtsvc;
	struct dp_virtsvc_lookup_entry *left;
	struct dp_virtsvc_lookup_entry *right;
};

const struct dp_virtsvc_lookup_entry *dp_virtsvc_get_ipv4_tree(void);
const struct dp_virtsvc_lookup_entry *dp_virtsvc_get_ipv6_tree(void);

static __rte_always_inline
int dp_virtsvc_ipv4_cmp(uint8_t proto1, rte_be32_t addr1, rte_be16_t port1,
						uint8_t proto2, rte_be32_t addr2, rte_be16_t port2)
{
	int diff;
	// this creates a diff between two Network-Byte-Order numbers
	// the tree structure will work fine, but the actual values (IPs, ports)
	// are not ordered properly, i.e. the semantics of the values are ignored
	// but for finding a service in the tree, it works fine

	diff = proto1 - proto2;
	if (diff)
		return diff;

	diff = addr1 - addr2;
	if (diff)
		return diff;

	return port1 - port2;
}

static __rte_always_inline
int dp_virtsvc_ipv6_cmp(uint8_t proto1, const union dp_ipv6 *addr1, rte_be16_t port1,
						uint8_t proto2, const union dp_ipv6 *addr2, rte_be16_t port2)
{
	int diff;
	// dtto, see above

	diff = proto1 - proto2;
	if (diff)
		return diff;

	diff = memcmp(addr1, addr2, 16);
	if (diff)
		return diff;

	return port1 - port2;
}

int dp_virtsvc_init(int socket_id);
void dp_virtsvc_free(void);

size_t dp_virtsvc_get_count(void);

int dp_virtsvc_get_pf_route(struct dp_virtsvc *virtsvc,
							 uint16_t vf_port_id,
							 rte_be32_t vf_ip,
							 rte_be16_t vf_l4_port,
							 uint16_t *pf_port_id,
							 int *conn_idx);

void dp_virtsvc_del_iface(uint16_t port_id);

int dp_virtsvc_get_used_ports_telemetry(struct rte_tel_data *dict);

int dp_virtsvc_open_sync_connection(rte_be32_t virtual_addr, rte_be16_t virtual_port, uint8_t proto,
									rte_be32_t vf_ip, rte_be16_t vf_l4_port, uint16_t vf_port_id,
									uint16_t conn_port);

void dp_synchronize_virtsvc_connections(void);

#ifdef __cplusplus
}
#endif
#endif
