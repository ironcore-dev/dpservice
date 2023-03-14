#ifndef __INCLUDE_DHCPV6_NODE_PRIV_H__
#define __INCLUDE_DHCPV6_NODE_PRIV_H__

#include <rte_ether.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	DHCPV6_CLIENT_PORT 546
#define	DHCPV6_SERVER_PORT 547

#define DHCPV6_FIXED_LEN	4
#define DP_UDP_HDR_SZ	8
#define OPTIONS_INDEX 4
#define INFINITY 0xffffffff
#define DP_DUMMY_HW_ID	0xabcd
/*
 * DHCPv6 message types
 */
#define DHCPV6_SOLICIT		    1
#define DHCPV6_ADVERTISE	    2
#define DHCPV6_REQUEST		    3
#define DHCPV6_CONFIRM		    4
#define DHCPV6_RENEW		    5
#define DHCPV6_REBIND		    6
#define DHCPV6_REPLY		    7
#define DHCPV6_RELEASE		    8
#define DHCPV6_DECLINE		    9
#define DHCPV6_RECONFIGURE	   10

/*
 * Status Codes
 */
#define STATUS_Success	0
#define STATUS_UnspecFail	1
#define STATUS_NoAddrsAvail	2
#define STATUS_NoBinding	3
#define STATUS_NotOnLink	4

/* DUID types
 */
#define DP_DUID_LLT	1
#define DP_DUID_EN	2
#define DP_DUID_LL	3
#define DP_DUID_UUID	4

/* DHCPv6 Option codes: */
#define DP_CLIENTID	1
#define DP_SERVERID	2
#define DP_IA_NA	3
#define DP_IA_TA	4
#define DP_IAADDR	5
#define DP_STATUS_CODE	13
#define DP_RAPID_COMMIT	14
#define DP_IA_PD	25
#define DP_IAPREFIX	26

/*
 * Normal packet format
 */
struct dhcpv6_packet {
	uint8_t msg_type;
	uint8_t transaction_id[3];
	uint8_t options[];
};

struct duid_t {
	uint16_t type;
	uint16_t hw_type;
	struct rte_ether_addr mac;
};

struct server_id {
	uint16_t op;
	uint16_t len;
	struct duid_t id;
};

struct client_id {
	uint16_t op;
	uint16_t len;
	uint8_t id[128];
};

struct rapid_commit {
	uint16_t op;
	uint16_t len;
};

struct status_code {
	uint16_t op;
	uint16_t len;
	uint16_t status;
};

struct ia_addr {
	uint8_t in6_addr[16];
	int32_t time_1;
	int32_t time_2;
	struct status_code code;
};

struct ia_addr_option {
	uint16_t op;
	uint16_t len;
	struct ia_addr addr;

};

struct ia {
	uint16_t ia_id;
	int32_t time_1;
	int32_t time_2;
	struct ia_addr_option addrv6;
};

struct ia_option {
	uint16_t op;
	uint16_t len;
	struct ia val;
};

struct dhcpv6_option {
	uint16_t op_code;
	uint16_t op_len;
	uint8_t data[];
};

enum
{
	DHCPV6_NEXT_DROP,
	DHCPV6_NEXT_MAX
};

struct dhcpv6_node_ctx
{
	uint16_t next;
};

struct dhcpv6_node_main {
	uint16_t next_index[DP_MAX_PORTS];
};

struct rte_node_register *dhcpv6_node_get(void);
int dhcpv6_set_next(uint16_t port_id, uint16_t next_index);
#ifdef __cplusplus
}
#endif
#endif
