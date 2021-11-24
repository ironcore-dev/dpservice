#ifndef __INCLUDE_IPV6_ND_NODE_H__
#define __INCLUDE_IPV6_ND_NODE_H__

#include "dpdk_layer.h"
//#include <linux/icmpv6.h>
//#include <linux/in6.h>

#ifdef __cplusplus
extern "C" {
#endif


/*
 *	ICMP codes for neighbour discovery messages
 */
#define NDISC_NEIGHBOUR_SOLICITATION	135
#define NDISC_NEIGHBOUR_ADVERTISEMENT	136

#define ND_OPT_LEN_OCTET_1	1

/*
 *	ndisc options
 */

enum {
	__ND_OPT_PREFIX_INFO_END = 0,
	ND_OPT_SOURCE_LL_ADDR = 1,	/* RFC2461 */
	ND_OPT_TARGET_LL_ADDR = 2
};


struct icmp6hdr {

	uint8_t	icmp6_type;
	uint8_t	icmp6_code;
	uint16_t	icmp6_cksum;

	union {

		struct icmpv6_nd_advt {
			uint32_t	reserved:5,
					override:1,
					solicited:1,
					router:1,
					reserved2:24;
		} u_nd_advt;

		struct icmpv6_nd_ra {
			uint8_t	hop_limit;
			uint8_t	reserved:3,
					router_pref:2,
					home_agent:1,
					other:1,
					managed:1;

			uint16_t	rt_lifetime;
		} u_nd_ra;

	} icmp6_dataun;
#define icmp6_router		icmp6_dataun.u_nd_advt.router
#define icmp6_solicited		icmp6_dataun.u_nd_advt.solicited
#define icmp6_override		icmp6_dataun.u_nd_advt.override
#define icmp6_ndiscreserved	icmp6_dataun.u_nd_advt.reserved
#define icmp6_hop_limit		icmp6_dataun.u_nd_ra.hop_limit
};


struct nd_msg {
	struct icmp6hdr	icmph;
	struct in6_addr	target;
	uint8_t	opt[];
};


enum
{
	IPV6_ND_NEXT_DROP,
	IPV6_ND_NEXT_MAX
};

struct ipv6_nd_node_ctx
{
	uint16_t next;
};

struct ipv6_nd_node_main {
	uint16_t next_index[DP_MAX_PORTS];
};

struct rte_node_register *ipv6_nd_node_get(void);
int ipv6_nd_set_next(uint16_t port_id, uint16_t next_index);
#ifdef __cplusplus
}
#endif
#endif
