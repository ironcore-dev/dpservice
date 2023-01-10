#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <rte_ethdev.h>
#include "dp_util.h"
#include "dp_netlink.h"
#include "dp_log.h"

static int dp_read_ngh(struct nlmsghdr *nh, int nll, struct rte_ether_addr *neigh,
						struct rte_ether_addr *own_mac)
{
	struct rtattr *rt_attr;
	char mac[24];
	struct ndmsg *rt_msg;
	int rtl, ndm_family;
	__be64 mac_num;

	for (; NLMSG_OK(nh, nll); nh = NLMSG_NEXT(nh, nll)) {
		rt_msg = (struct ndmsg *)NLMSG_DATA(nh);
		rt_attr = (struct rtattr *)RTM_RTA(rt_msg);
		ndm_family = rt_msg->ndm_family;
		if ((ndm_family != AF_INET6) || (rt_msg->ndm_state == NUD_NOARP))
			continue;
		if (rt_msg->ndm_flags & NTF_ROUTER) {
			rtl = RTM_PAYLOAD(nh);
			for (; RTA_OK(rt_attr, rtl); rt_attr = RTA_NEXT(rt_attr, rtl))
				if (rt_attr->rta_type == NDA_LLADDR) {
					sprintf(mac, "%lld", *((__be64 *)RTA_DATA(rt_attr)));
					mac_num = atol(mac);
					memcpy(neigh, &mac_num, sizeof(*neigh));
					memset(&mac_num, 0, sizeof(mac_num));
				}
			if (!DP_MAC_EQUAL(own_mac, neigh))
				return 0;
		}
	}
	return -1;
}

static int dp_recv_msg(struct sockaddr_nl sock_addr, int sock, char* buf_ptr)
{
	struct nlmsghdr *nh;
	int len, nll = 0;

	while (1) {
		len = recv(sock, buf_ptr, DP_NLINK_BUF_SIZE - nll, 0);
		if (len < 0)
			return len;

		nh = (struct nlmsghdr *)buf_ptr;

		if (nh->nlmsg_type == NLMSG_DONE)
			break;
		buf_ptr += len;
		nll += len;
		if ((sock_addr.nl_groups & RTMGRP_NEIGH) == RTMGRP_NEIGH)
			break;

		if ((sock_addr.nl_groups & RTMGRP_IPV6_ROUTE) == RTMGRP_IPV6_ROUTE)
			break;
	}
	return nll;
}

int dp_get_pf_neigh_mac(int if_idx, struct rte_ether_addr* neigh, struct rte_ether_addr* own_mac)
{ 
	struct dp_nlnk_req *req;
	struct sockaddr_nl sa;
	char *dp_nlink_reply;
	struct nlmsghdr *nh;
	int sock, seq = 0;
	struct msghdr msg;
	struct iovec iov;
	int ret = 0;
	int nll;

	sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (sock < 0) {
		printf("open netlink socket: %s\n", strerror(errno));
		return -1;
	}
	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;
	sa.nl_groups = RTMGRP_NEIGH;
	if (bind(sock, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		printf("bind to netlink: %s\n", strerror(errno));
		ret = -1;
		goto cleanup;
	}
	req = malloc(sizeof(struct dp_nlnk_req));
	if (!req)
		goto cleanup;
	
	memset(req, 0, sizeof(struct dp_nlnk_req));
	req->nl.nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg) + sizeof(struct dp_nl_tlv));
	req->nl.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	req->nl.nlmsg_type = RTM_GETNEIGH;
	req->rt.ndm_type = RTN_UNSPEC;
	req->rt.ndm_family = AF_INET6;
	req->nl.nlmsg_pid = 0;
	req->nl.nlmsg_seq = ++seq;

	req->if_tlv.length = sizeof(struct dp_nl_tlv);
	req->if_tlv.type = NDA_IFINDEX;
	req->if_tlv.val = if_idx;
	memset(&msg, 0, sizeof(msg));
	iov.iov_base = (void *)&req->nl;
	iov.iov_len = req->nl.nlmsg_len;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	ret = sendmsg(sock, &msg, 0);
	if (ret < 0) {
		printf("send to netlink: %s\n", strerror(errno));
		ret = -1;
		goto err1;
	}
	dp_nlink_reply = malloc(DP_NLINK_BUF_SIZE);
	memset(dp_nlink_reply, 0, DP_NLINK_BUF_SIZE);
	if (!dp_nlink_reply)
		goto err1;
	nll = dp_recv_msg(sa, sock, dp_nlink_reply);
	if (nll < 0) {
		printf("recv from netlink: %s\n", strerror(nll));
		ret = -1;
		goto err2;
	}
	nh = (struct nlmsghdr *)dp_nlink_reply;
	// TODO this should be an error in production
	if (dp_read_ngh(nh, nll, neigh, own_mac) < 0)
		DPS_LOG_WARNING("No neighboring router found");

err2:
	free(dp_nlink_reply);
err1:
	free(req);
cleanup:
	close(sock);
	return ret;
}
