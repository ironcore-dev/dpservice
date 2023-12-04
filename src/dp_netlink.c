// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <rte_ethdev.h>
#include "dp_error.h"
#include "dp_log.h"
#include "dp_netlink.h"
#include "dp_util.h"

static int dp_read_neigh(struct nlmsghdr *nh, __u32 nll, struct rte_ether_addr *neigh,
						 const struct rte_ether_addr *own_mac)
{
	struct rtattr *rt_attr;
	struct ndmsg *rt_msg;
	size_t rtl, ndm_family;

	for (; NLMSG_OK(nh, nll); nh = NLMSG_NEXT(nh, nll)) {
		rt_msg = (struct ndmsg *)NLMSG_DATA(nh);
		rt_attr = (struct rtattr *)RTM_RTA(rt_msg);
		ndm_family = rt_msg->ndm_family;
		if ((ndm_family != AF_INET6) || (rt_msg->ndm_state == NUD_NOARP))
			continue;
		if (rt_msg->ndm_flags & NTF_ROUTER) {
			rtl = RTM_PAYLOAD(nh);
			for (; RTA_OK(rt_attr, rtl); rt_attr = RTA_NEXT(rt_attr, rtl)) {
				if (rt_attr->rta_type == NDA_LLADDR)
					memcpy(&neigh->addr_bytes, RTA_DATA(rt_attr), sizeof(neigh->addr_bytes));
			}
			if (!DP_MAC_EQUAL(own_mac, neigh))
				return DP_OK;
		}
	}
	return DP_ERROR;
}

static int dp_recv_msg(struct sockaddr_nl sock_addr, int sock, char *buf, int bufsize)
{
	struct nlmsghdr *nh;
	ssize_t recv_len;
	ssize_t msg_len = 0;

	for (;;) {
		recv_len = recv(sock, buf, bufsize - msg_len, 0);
		if (recv_len < 0)
			return (int)recv_len;

		nh = (struct nlmsghdr *)buf;
		if (nh->nlmsg_type == NLMSG_DONE)
			break;

		buf += recv_len;
		msg_len += recv_len;

		if ((sock_addr.nl_groups & RTMGRP_NEIGH) == RTMGRP_NEIGH)
			break;
		if ((sock_addr.nl_groups & RTMGRP_IPV6_ROUTE) == RTMGRP_IPV6_ROUTE)
			break;
	}
	return (int)msg_len;
}

int dp_get_pf_neigh_mac(int if_idx, struct rte_ether_addr *neigh, const struct rte_ether_addr *own_mac)
{
	struct sockaddr_nl sa = {
		.nl_family = AF_NETLINK,
		.nl_groups = RTMGRP_NEIGH,
	};
	struct dp_nlnk_req req = {
		.nl.nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg) + sizeof(struct dp_nl_tlv)),
		.nl.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP,
		.nl.nlmsg_type = RTM_GETNEIGH,
		.rt.ndm_type = RTN_UNSPEC,
		.rt.ndm_family = AF_INET6,
		.nl.nlmsg_pid = 0,
		.nl.nlmsg_seq = 1,
		.if_tlv.length = sizeof(struct dp_nl_tlv),
		.if_tlv.type = NDA_IFINDEX,
		.if_tlv.val = if_idx,
	};
	struct iovec iov = {
		.iov_base = &req.nl,
		.iov_len = req.nl.nlmsg_len,
	};
	struct msghdr msg = {
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};
	int sock;
	char reply[DP_NLINK_BUF_SIZE];
	int reply_len;
	int ret = DP_ERROR;

	sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (sock < 0) {
		DPS_LOG_ERR("Cannot open netlink socket", DP_LOG_NETLINK(strerror(errno)));
		return DP_ERROR;
	}

	if (bind(sock, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		DPS_LOG_ERR("Cannot bind to netlink", DP_LOG_NETLINK(strerror(errno)));
		goto cleanup;
	}

	if (sendmsg(sock, &msg, 0) < 0) {
		DPS_LOG_ERR("Cannot send message to netlink", DP_LOG_NETLINK(strerror(errno)));
		goto cleanup;
	}

	reply_len = dp_recv_msg(sa, sock, reply, sizeof(reply));
	if (reply_len < 0) {
		DPS_LOG_ERR("Cannot receive message from netlink", DP_LOG_NETLINK(strerror(reply_len)));
		goto cleanup;
	}

	// TODO this should be an error in production
	if (DP_FAILED(dp_read_neigh((struct nlmsghdr *)reply, reply_len, neigh, own_mac)))
		DPS_LOG_WARNING("No neighboring router found");

	ret = DP_OK;

cleanup:
	close(sock);
	return ret;
}
