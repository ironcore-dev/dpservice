#ifndef __INCLUDE_DP_NETLINK_H__
#define __INCLUDE_DP_NETLINK_H__

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

int dp_get_pf_neigh_mac(int if_idx, struct rte_ether_addr *neigh, const struct rte_ether_addr *own_mac);

#ifdef __cplusplus
}
#endif
#endif
