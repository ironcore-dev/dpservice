#ifndef __INCLUDE_DP_DHCPV6_H__
#define __INCLUDE_DP_DHCPV6_H__

#include <stdint.h>
#include <rte_ether.h>

#define	DHCPV6_CLIENT_PORT	546
#define	DHCPV6_SERVER_PORT	547

#define DHCPV6_INFINITY 0xffffffff

/*
 * Message types
 */
#define DHCPV6_SOLICIT		1
#define DHCPV6_ADVERTISE	2
#define DHCPV6_REQUEST		3
#define DHCPV6_CONFIRM		4
#define DHCPV6_RENEW		5
#define DHCPV6_REBIND		6
#define DHCPV6_REPLY		7
#define DHCPV6_RELEASE		8
#define DHCPV6_DECLINE		9
#define DHCPV6_RECONFIGURE	10

/*
 * Status Codes
 */
#define DHCPV6_STATUS_SUCCESS		0
#define DHCPV6_STATUS_UNSPECFAIL	1
#define DHCPV6_STATUS_NOADDRSAVAIL	2
#define DHCPV6_STATUS_NOBINDING		3
#define DHCPV6_STATUS_NOTONLINK		4

/*
 * DUID types
 */
#define DHCPV6_DUID_LLT		1
#define DHCPV6_DUID_EN		2
#define DHCPV6_DUID_LL		3
#define DHCPV6_DUID_UUID	4

/*
 * Option codes
 */
#define DHCPV6_OPT_CLIENTID		1
#define DHCPV6_OPT_SERVERID		2
#define DHCPV6_OPT_IA_NA		3
#define DHCPV6_OPT_IA_TA		4
#define DHCPV6_OPT_IAADDR		5
#define DHCPV6_OPT_STATUS_CODE	13
#define DHCPV6_OPT_RAPID_COMMIT	14
#define DHCPV6_OPT_IA_PD		25
#define DHCPV6_OPT_IAPREFIX		26

// General definitions as per RFC
struct dhcpv6_packet {
	uint8_t msg_type;
	uint8_t transaction_id[3];
	uint8_t options[];
};

struct dhcpv6_option {
	uint16_t op_code;
	uint16_t op_len;
	uint8_t data[];
};

// client id can be of any type, this is the maximum size allowed
struct dhcpv6_opt_client_id {
	uint16_t op_code;
	uint16_t op_len;
	uint8_t id[128];
};

struct dhcpv6_ia_na {
	uint32_t iaid;
	uint32_t t1;
	uint32_t t2;
	struct dhcpv6_option options[];
};

struct dhcpv6_opt_ia_na {
	uint16_t op_code;
	uint16_t op_len;
	struct dhcpv6_ia_na ia_na;
};

struct dhcpv6_ia_addr {
	uint8_t  ipv6[16];
	uint32_t preferred_lifetime;
	uint32_t valid_lifetime;
	struct dhcpv6_option options[];
};

struct dhcpv6_opt_ia_addr {
	uint16_t op_code;
	uint16_t op_len;
	struct dhcpv6_ia_addr addr;
};

struct dhcpv6_opt_status_code {
	uint16_t op_code;
	uint16_t op_len;
	uint16_t status;
};

struct dhcpv6_duid_ll {
	uint16_t type;
	uint16_t hw_type;
	struct rte_ether_addr mac;
};

// Specific definitions for easier work with options in dp-service

struct dhcpv6_opt_server_id_ll {
	uint16_t op_code;
	uint16_t op_len;
	struct dhcpv6_duid_ll id;
};

struct dhcpv6_ia_addr_status {
	uint8_t  ipv6[16];
	uint32_t preferred_lifetime;
	uint32_t valid_lifetime;
	struct dhcpv6_opt_status_code options[1];
};
struct dhcpv6_opt_ia_addr_status {
	uint16_t op_code;
	uint16_t op_len;
	struct dhcpv6_ia_addr_status addr;
};
struct dhcpv6_ia_na_single_addr_status {
	uint32_t iaid;
	uint32_t t1;
	uint32_t t2;
	struct dhcpv6_opt_ia_addr_status options[1];
};
struct dhcpv6_opt_ia_na_single_addr_status {
	uint16_t op_code;
	uint16_t op_len;
	struct dhcpv6_ia_na_single_addr_status ia_na;
};

#endif
