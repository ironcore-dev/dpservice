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
#define DP_DHCP_USR_CLS_INF	0x4D
#define DP_DHCP_VND_CLS_IDT	0x3C
#define DP_DHCP_MTU			0x1A

/* DHCP message types. */
#define DHCPDISCOVER	1
#define DHCPOFFER	2
#define DHCPREQUEST	3
#define DHCPDECLINE	4
#define DHCPACK	5
#define DP_DHCP_LEASE_MSG	0x33

#define DP_DHCP_ROUTER		0x03
#define DP_DHCP_END			0xFF
#define DP_DHCP_OFFER		0x02
#define DP_DHCP_ACK			0x05
#define DP_DHCP_INFINITE	0xffffffff
#define DP_DHCP_MASK		0xffffffff
#define DP_DHCP_MTU_VALUE	0x00578

#define DHCP_MAGIC_COOKIE 0x63825363

#define DHCP_UDP_OVERHEAD	(20 + /* IP header */			\
			    	8)   /* UDP header */
#define DHCP_FIXED_NON_UDP	236 + 4 /* Magic cookie 4 bytes */
#define DHCP_FIXED_LEN	(DHCP_FIXED_NON_UDP + DHCP_UDP_OVERHEAD)
#define DHCP_MTU_MAX	1500
#define DHCP_MTU_MIN	576

#define DHCP_MAX_OPTION_LEN	(DHCP_MTU_MAX - DHCP_FIXED_LEN)
#define DHCP_MIN_OPTION_LEN     (DHCP_MTU_MIN - DHCP_FIXED_LEN)

#define DHCP_HEADER_LEN 236

#define DP_USER_CLASS_INF_SIZE	5
#define DP_VND_CLASS_IDENT		33

#define DP_USER_CLASS_INF_COMP_STR	"iPXE"
#define DP_VND_CLS_IDT_COMP_STR		"PXEClient:Arch:00007"
#define DP_PXE_TFTP_PATH			"ipxe/x86_64/ipxe.new"

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
	uint8_t		options[DHCP_MIN_OPTION_LEN];
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

typedef enum dp_pxe_mode {
	DP_PXE_MODE_NONE,
	DP_PXE_MODE_TFTP,
	DP_PXE_MODE_HTTP,
} dp_pxe_mode;

struct rte_node_register *dhcp_node_get(void);
int dhcp_set_next(uint16_t port_id, uint16_t next_index);
#ifdef __cplusplus
}
#endif
#endif