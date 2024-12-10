// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#ifndef __INCLUDE_DP_UTIL_H__
#define __INCLUDE_DP_UTIL_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <net/if.h>
#include <rte_byteorder.h>
#include <rte_ethdev.h>
#include <rte_hash.h>
#include <rte_log.h>
#include <rte_mbuf.h>

#define DP_IFACE_PXE_MAX_LEN	32
#define DP_LB_ID_MAX_LEN		64
#define DP_LB_MAX_PORTS			16

#define DP_MAC_EQUAL(mac1, mac2) (((mac1)->addr_bytes[0] == (mac2)->addr_bytes[0]) && \
								((mac1)->addr_bytes[1] == (mac2)->addr_bytes[1]) && \
								((mac1)->addr_bytes[2] == (mac2)->addr_bytes[2]) && \
								((mac1)->addr_bytes[3] == (mac2)->addr_bytes[3]) && \
								((mac1)->addr_bytes[4] == (mac2)->addr_bytes[4]) && \
								((mac1)->addr_bytes[5] == (mac2)->addr_bytes[5]))

#define DP_TCP_HDR_LEN(TCP_HDR) (((TCP_HDR)->data_off & 0xf0) >> 2)

#define DP_TCP_PKT_FLAG_SYN(FLAGS) ((FLAGS) & RTE_TCP_SYN_FLAG)
#define DP_TCP_PKT_FLAG_RST(FLAGS) ((FLAGS) & RTE_TCP_RST_FLAG)
#define DP_TCP_PKT_FLAG_ACK(FLAGS) ((FLAGS) & RTE_TCP_ACK_FLAG)
#define DP_TCP_PKT_FLAG_FIN(FLAGS) ((FLAGS) & RTE_TCP_FIN_FLAG)
#define DP_TCP_PKT_FLAG_SYNACK(FLAGS) \
	(((FLAGS) & (RTE_TCP_SYN_FLAG|RTE_TCP_ACK_FLAG)) == (RTE_TCP_SYN_FLAG|RTE_TCP_ACK_FLAG))

#define DP_TCP_PKT_FLAG_EXACT(FLAGS, REQUIRED) \
    (((FLAGS) & 0xFF) == (REQUIRED))
#define DP_TCP_PKT_FLAG_ONLY_SYN(FLAGS) \
    DP_TCP_PKT_FLAG_EXACT((FLAGS), RTE_TCP_SYN_FLAG)
#define DP_TCP_PKT_FLAG_ONLY_ACK(FLAGS) \
    DP_TCP_PKT_FLAG_EXACT((FLAGS), RTE_TCP_ACK_FLAG)
#define DP_TCP_PKT_FLAG_ONLY_SYNACK(FLAGS) \
    DP_TCP_PKT_FLAG_EXACT((FLAGS), (RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG))


int dp_get_dev_info(uint16_t port_id, struct rte_eth_dev_info *dev_info, char ifname[IF_NAMESIZE]);

int dp_get_num_of_vfs(void);


struct rte_hash *dp_create_jhash_table(int capacity, size_t key_len, const char *name, int socket_id);

void dp_free_jhash_table(struct rte_hash *table);

int dp_set_vf_rate_limit(uint16_t port_id, uint64_t rate);


#ifdef __cplusplus
}
#endif
#endif
