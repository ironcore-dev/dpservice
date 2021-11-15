#ifndef __INCLUDE_DHCP_NODE_PRIV_H__
#define __INCLUDE_DHCP_NODE_PRIV_H__

#include "dpdk_layer.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DP_BOOTP_SRV_PORT	67
#define DP_BOOTP_CLNT_PORT	68
#define DP_BOOTP_REQUEST	1
#define DP_BOOTP_REPLY		2

#define DP_DHCP_MSG_TYPE	0x35
#define DP_DHCP_SRV_IDENT	0x36
#define DP_DHCP_STATIC_ROUT	0x79
#define DP_DHCP_SUBNET_MASK	0x01
#define DP_DHCP_MTU			0x1A

#define DP_DHCP_LEASE_MSG	0x33
#define DP_DHCP_ROUTER		0x03
#define DP_DHCP_END			0xFF
#define DP_DHCP_OFFER		0x02
#define DP_DHCP_ACK			0x05
#define DP_DHCP_INFINITE	0xffffffff
#define DP_DHCP_MASK		0xffffffff
#define DP_DHCP_MTU_VALUE	0x005DC

#define DHCP_MAGIC_COOKIE 0x63825363

#define DHCP_HEADER_LEN 236

struct dp_dhcp_header {
	uint8_t		op;
	uint8_t		htype;
	uint8_t		hlen;
	uint8_t		hops;
	uint32_t	xid;
	uint16_t	secs;
	uint16_t	flags;
	uint32_t	ciaddr;
	uint32_t	yiaddr;
	uint32_t	siaddr;
	uint32_t	giaddr;
	uint8_t		chaddr[16];
	char		sname[64];
	char		file[128];
	uint32_t	magic;
	uint8_t		vend[60];
};
#define DP_DHCP_HEADER_LEN == sizeof(struct dp_dhcp_header))

enum
{
	DHCP_NEXT_DROP,
	DHCP_NEXT_MAX
};

struct dhcp_node_ctx
{
	uint16_t next;
};

struct dhcp_node_main {
	uint16_t next_index[DP_MAX_PORTS];
};

struct rte_node_register *dhcp_node_get(void);
int dhcp_set_next(uint16_t port_id, uint16_t next_index);
#ifdef __cplusplus
}
#endif
#endif