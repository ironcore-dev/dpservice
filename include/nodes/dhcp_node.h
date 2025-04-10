// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#ifndef __INCLUDE_DHCP_NODE_H__
#define __INCLUDE_DHCP_NODE_H__

#include <stdint.h>
#include <rte_byteorder.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DP_BOOTP_SRV_PORT 67
#define DP_BOOTP_CLI_PORT 68
#define DP_BOOTP_REQUEST  1
#define DP_BOOTP_REPLY    2

/* DHCP options; RFC 2132, 3004, 3442 */
#define DHCP_OPT_PAD             0
#define DHCP_OPT_SUBNET_MASK     1
#define DHCP_OPT_ROUTER          3
#define DHCP_OPT_DNS             6
#define DHCP_OPT_HOSTNAME        12
#define DHCP_OPT_INTERFACE_MTU   26
#define DHCP_OPT_IP_LEASE_TIME   51
#define DHCP_OPT_MESSAGE_TYPE    53
#define DHCP_OPT_SERVER_ID       54
#define DHCP_OPT_VENDOR_CLASS_ID 60
#define DHCP_OPT_USER_CLASS      77
#define DHCP_OPT_CLASSLESS_ROUTE 121
#define DHCP_OPT_END             255

/* DHCP message types; RFC 2132 */
#define DHCPDISCOVER 1
#define DHCPOFFER    2
#define DHCPREQUEST  3
#define DHCPDECLINE  4
#define DHCPACK      5

#define DP_DHCP_INFINITE 0xffffffff
#define DP_DHCP_MASK_NL  0xffffffff

#define DHCP_MAGIC_COOKIE 0x63825363

#define DHCP_MTU_MAX 1500

#define DHCP_MAX_OPTIONS_LEN \
	(DHCP_MTU_MAX \
	- sizeof(struct rte_ether_hdr) \
	- sizeof(struct rte_ipv4_hdr) \
	- sizeof(struct rte_udp_hdr) \
	- offsetof(struct dp_dhcp_header, options))

#define DP_USER_CLASS_INF_COMP_STR "iPXE"
#define DP_VND_CLASS_ID_COMP_STR   "PXEClient:Arch:00007"
#define DP_PXE_TFTP_PATH           "ipxe/x86_64/ipxe.new"

#define DP_USER_CLASS_INF_LEN (sizeof(DP_USER_CLASS_INF_COMP_STR)-1)
#define DP_VND_CLASS_ID_LEN   (sizeof(DP_VND_CLASS_ID_COMP_STR)-1)

struct dp_dhcp_header {
	uint8_t		op;
	uint8_t		htype;
	uint8_t		hlen;
	uint8_t		hops;
	rte_be32_t	xid;
	rte_be16_t	secs;
	rte_be16_t	flags;
	rte_be32_t	ciaddr;
	rte_be32_t	yiaddr;
	rte_be32_t	siaddr;
	rte_be32_t	giaddr;
	uint8_t		chaddr[16];
	char		sname[64];
	char		file[128];
	rte_be32_t	magic;
	uint8_t		options[1];
};

enum dp_pxe_mode {
	DP_PXE_MODE_NONE,
	DP_PXE_MODE_TFTP,
	DP_PXE_MODE_HTTP,
};

int dhcp_node_append_vf_tx(uint16_t port_id, const char *tx_node_name);

#ifdef __cplusplus
}
#endif
#endif
