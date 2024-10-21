// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#ifndef __INCLUDE_DP_NETLINK_H__
#define __INCLUDE_DP_NETLINK_H__

#include <stdint.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#define DP_NLINK_BUF_SIZE 8192

#ifdef __cplusplus
extern "C" {
#endif

struct dp_nl_tlv {
	uint16_t length;
	uint16_t type;
	uint32_t val;
};

struct dp_nlnk_req {
	struct nlmsghdr nl;
	struct ndmsg rt;
	struct dp_nl_tlv if_tlv;
};

int dp_get_pf_neigh_mac(uint32_t if_idx, struct rte_ether_addr *neigh, const struct rte_ether_addr *own_mac);

#ifdef __cplusplus
}
#endif
#endif
