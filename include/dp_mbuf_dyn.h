#ifndef __INCLUDE_DP_MBUF_DYN_H__
#define __INCLUDE_DP_MBUF_DYN_H__

#include <assert.h>
#include <rte_common.h>
#include <rte_flow.h>
#ifdef ENABLE_GRAPHTRACE
#	include <rte_atomic.h>
#endif
#include "dp_flow.h"
#ifdef ENABLE_VIRTSVC
#	include "dp_virtsvc.h"
#endif

#define DP_MBUF_PRIV_DATA_SIZE (RTE_CACHE_LINE_SIZE * 2)

#ifdef __cplusplus
extern "C" {
#endif


#define	RTE_PTYPE_CUSTOMIZED_DP_RECIRC 0x10000000
#define	RTE_PTYPE_CUSTOMIZED_DP_INTERNAL_MASK (~RTE_PTYPE_ALL_MASK)

#define DP_PTYPE_IS_RECIRC(ptype) \
	((ptype & RTE_PTYPE_CUSTOMIZED_DP_INTERNAL_MASK) == RTE_PTYPE_CUSTOMIZED_DP_RECIRC)


enum dp_periodic_type {
	DP_PER_TYPE_ZERO,
	DP_PER_TYPE_ND_RA,
	DP_PER_TYPE_DIRECT_TX,
} __rte_packed;

struct dp_flow {
	struct {
		uint16_t	flow_type : 2;		// local,outgoing,incoming
		uint16_t	public_flow : 1;
		uint16_t	overlay_type: 1;	// supported overlay type
		uint16_t	nat : 3;
		uint16_t	offload_ipv6 : 1;	// tmp solution to set if we should offload ipv6 pkts
		uint16_t	dir : 2;			// store the direction of each packet
		uint16_t	offload_decision: 2;	// store the offload status of each packet
	} flags;
	uint16_t	l3_type;  //layer-3 for inner packets. it can be crafted or extracted from raw frames
	union {
		uint32_t	dst_addr;
		uint8_t		dst_addr6[16];
	} dst;
	union {
		uint32_t	src_addr;
		uint8_t		src_addr6[16];
	} src;
	uint32_t	nat_addr;
	uint16_t	nat_port;

	uint8_t					l4_type;
	union {
		struct {
			uint16_t		dst_port;
			uint16_t		src_port;
		} trans_port;
		struct {
			uint8_t			icmp_type;
			uint8_t			icmp_code;
			uint16_t		icmp_identifier;
		} icmp_field;
	} l4_info;

	uint32_t		dp_flow_hash;

	struct {
		uint8_t		ul_src_addr6[16];
		uint8_t		ul_dst_addr6[16];
		uint16_t 	l3_type;	//layer-3 type in ethernet header of outter packets
		uint8_t		proto_id;	//proto_id in outter ipv6 header
		uint16_t	src_port;	//src_port in outter udp header
		uint16_t	dst_port;	//dst_port in outter udp header
		uint32_t	dst_vni;
	} tun_info;
	uint8_t					vnf_type;
	uint8_t					nxt_hop;
	enum dp_periodic_type	periodic_type;
	struct flow_value	*conntrack;
#ifdef ENABLE_VIRTSVC
	struct dp_virtsvc	*virtsvc;
#endif
};

struct dp_pkt_mark {
#ifdef ENABLE_GRAPHTRACE
	uint32_t id;
#endif
	uint32_t flags;
	// check the init function if adding more,
	// due to this being small, memset has not been used
};

static_assert(sizeof(struct dp_flow) + sizeof(struct dp_pkt_mark) <= DP_MBUF_PRIV_DATA_SIZE,
			  "packet private data is too big to fit in packet");
static_assert(sizeof(((struct dp_flow *)0)->periodic_type) == 1,
			  "enum dp_periodic_type is unnecessarily big");
static_assert((1 << (sizeof(((struct dp_flow *)0)->nxt_hop) * 8)) >= DP_MAX_PORTS,
			  "struct dp_flow::nxt_hop cannot hold all possible port_ids");

#ifdef ENABLE_GRAPHTRACE
extern rte_atomic32_t dp_pkt_id_counter;
#endif

static __rte_always_inline struct dp_flow *dp_get_flow_ptr(struct rte_mbuf *m)
{
	assert(m);
	return (struct dp_flow *)(m + 1);
}

static __rte_always_inline struct dp_flow *dp_init_flow_ptr(struct rte_mbuf *m)
{
	struct dp_flow *df = dp_get_flow_ptr(m);

	memset(df, 0, sizeof(*df));

	return df;
}

static __rte_always_inline struct dp_pkt_mark *dp_get_pkt_mark(struct rte_mbuf *m)
{
	return (struct dp_pkt_mark *)(dp_get_flow_ptr(m) + 1);
}

static __rte_always_inline void dp_init_pkt_mark(struct rte_mbuf *m)
{
	struct dp_pkt_mark *mark = dp_get_pkt_mark(m);

#ifdef ENABLE_GRAPHTRACE
	mark->id = rte_atomic32_add_return(&dp_pkt_id_counter, 1);
#endif
	mark->flags = 0;
}

#ifdef __cplusplus
}
#endif
#endif
