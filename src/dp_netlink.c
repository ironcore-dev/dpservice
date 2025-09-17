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
#include "dp_port.h"

static int dp_nl_read_neigh(struct nlmsghdr *nh, __u32 nll, struct rte_ether_addr *neigh,
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
			// If it is a tap device, we make an exception with own MAC address check. FeBOX case
			if (dp_conf_is_tap_mode())
				return DP_OK;
			if (!DP_MAC_EQUAL(own_mac, neigh))
				return DP_OK;
		}
	}
	return DP_ERROR;
}

static int dp_nl_recv_neigh_msg(struct sockaddr_nl sock_addr, int sock, char *buf, int bufsize)
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

int dp_nl_get_pf_neigh_mac(uint32_t if_idx, struct rte_ether_addr *neigh, const struct rte_ether_addr *own_mac)
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

	reply_len = dp_nl_recv_neigh_msg(sa, sock, reply, sizeof(reply));
	if (reply_len < 0) {
		DPS_LOG_ERR("Cannot receive message from netlink", DP_LOG_NETLINK(strerror(reply_len)));
		goto cleanup;
	}

	ret = dp_nl_read_neigh((struct nlmsghdr *)reply, reply_len, neigh, own_mac);

cleanup:
	close(sock);
	return ret;
}


static int dp_nl_send_recv_vf_rate_msg(int sock, struct dp_nl_vf_rate_req *req)
{
	ssize_t reply_len, sent_len;
	char reply[4096];
	struct nlmsghdr *nh;
	struct nlmsgerr *err;

	struct sockaddr_nl sa = {
		.nl_family = AF_NETLINK,
	};

	if (bind(sock, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		DPS_LOG_ERR("Cannot bind to netlink", DP_LOG_NETLINK(strerror(errno)));
		return DP_ERROR;
	}

	sent_len = send(sock, req, req->nl.nlmsg_len, 0);
	if (sent_len < 0 || sent_len != req->nl.nlmsg_len) {
		DPS_LOG_ERR("Failed to send VF rate message", DP_LOG_NETLINK(strerror(errno)));
		return DP_ERROR;
	}

	// Wait for ACK
	reply_len = recv(sock, reply, sizeof(reply), 0);
	if (reply_len < (ssize_t)NLMSG_LENGTH(sizeof(struct nlmsgerr))) {
		DPS_LOG_ERR("Cannot receive ACK from netlink", DP_LOG_NETLINK(strerror(errno)));
		return DP_ERROR;
	}

	nh = (struct nlmsghdr *)reply;
	if (nh->nlmsg_type == NLMSG_ERROR) {
		err = (struct nlmsgerr *)NLMSG_DATA(nh);
		if (err->error != 0) {
			DPS_LOG_ERR("Netlink error setting VF rate", DP_LOG_NETLINK(strerror(-err->error)));
			return DP_ERROR;
		}
	} else {
		DPS_LOG_ERR("Unexpected netlink response type", DP_LOG_NETLINK(nh->nlmsg_type));
		return DP_ERROR;
	}

	return DP_OK;
}

int dp_nl_set_vf_rate(uint32_t pf_if_idx, uint32_t vf_index, uint32_t min_tx_rate, uint32_t max_tx_rate)
{
	struct dp_nl_vf_rate_req req = {0};
	struct rtattr *linkinfo, *vfinfo, *vfrate;
	struct ifla_vf_rate *rate;
	int sock;
	int ret;

	req.nl.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.nl.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	req.nl.nlmsg_type = RTM_SETLINK;
	req.ifi.ifi_family = AF_UNSPEC;
	req.ifi.ifi_index = pf_if_idx;

	linkinfo = (struct rtattr *)((char *)&req + NLMSG_ALIGN(req.nl.nlmsg_len));
	linkinfo->rta_type = IFLA_VFINFO_LIST;
	linkinfo->rta_len = RTA_LENGTH(0);

	vfinfo = (struct rtattr *)((char *)linkinfo + RTA_ALIGN(linkinfo->rta_len));
	vfinfo->rta_type = IFLA_VF_INFO;
	vfinfo->rta_len = RTA_LENGTH(0);

	// Add IFLA_VF_RATE attribute
	vfrate = (struct rtattr *)((char *)vfinfo + RTA_ALIGN(vfinfo->rta_len));
	vfrate->rta_type = IFLA_VF_RATE;
	vfrate->rta_len = RTA_LENGTH(sizeof(struct ifla_vf_rate));

	rate = (struct ifla_vf_rate *)RTA_DATA(vfrate);
	rate->vf = vf_index;
	rate->min_tx_rate = min_tx_rate;
	rate->max_tx_rate = max_tx_rate;

	// Update lengths
	vfinfo->rta_len += (unsigned short)RTA_ALIGN(vfrate->rta_len);
	linkinfo->rta_len += (unsigned short)RTA_ALIGN(vfinfo->rta_len);
	req.nl.nlmsg_len += RTA_ALIGN(linkinfo->rta_len);

	sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (sock < 0) {
		DPS_LOG_ERR("Cannot open netlink socket", DP_LOG_NETLINK(strerror(errno)));
		return DP_ERROR;
	}

	ret = dp_nl_send_recv_vf_rate_msg(sock, &req);
	close(sock);

	return ret;
}
