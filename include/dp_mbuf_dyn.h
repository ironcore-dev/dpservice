#ifndef __INCLUDE_DP_MBUF_DYN_H__
#define __INCLUDE_DP_MBUF_DYN_H__

#include <assert.h>
#include <rte_common.h>
#include <rte_flow.h>
#include <rte_atomic.h>
#include "dp_error.h"
#include "dp_flow.h"
#ifdef ENABLE_VIRTSVC
#	include "dp_virtsvc.h"
#endif
#include "dp_vnf.h"

#define DP_MBUF_PRIV_DATA_SIZE (RTE_CACHE_LINE_SIZE * 2)

#ifdef __cplusplus
extern "C" {
#endif

struct dp_flow {
	struct {
		uint16_t	public_flow : 1;
		uint16_t	overlay_type : 1;		// supported overlay type
		uint16_t	nat : 3;
		uint16_t	offload_ipv6 : 1;		// tmp solution to set if we should offload ipv6 pkts
		uint16_t	dir : 2;				// store the direction of each packet
		uint16_t	offload_decision : 2;	// store the offload status of each packet
	} flags;
	uint16_t	l3_type;  //layer-3 for inner packets. it can be crafted or extracted from raw frames
	union {
		rte_be32_t	dst_addr;
		uint8_t		dst_addr6[16];
	} dst;
	union {
		rte_be32_t	src_addr;
		uint8_t		src_addr6[16];
	} src;
	rte_be32_t	nat_addr;
	uint16_t	nat_port;

	uint8_t					l4_type;
	union {
		struct {
			rte_be16_t		dst_port;
			rte_be16_t		src_port;
		} trans_port;
		struct {
			uint8_t			icmp_type;
			uint8_t			icmp_code;
			rte_be16_t		icmp_identifier;
		} icmp_field;
	} l4_info;

	uint32_t		dp_flow_hash;  // TODO: could be brought down to 1-bit as it only chooses PF0/PF1 in ipv4_lookup

	struct {
		uint8_t		ul_src_addr6[16];
		uint8_t		ul_dst_addr6[16];
		uint16_t 	l3_type;	//layer-3 type in ethernet header of outer packets
		uint8_t		proto_id;	//proto_id in outer ipv6 header
		uint32_t	dst_vni;
	} tun_info;
	enum dp_vnf_type	vnf_type;
	uint8_t				nxt_hop;
	struct flow_value	*conntrack;
#ifdef ENABLE_VIRTSVC
	struct dp_virtsvc	*virtsvc;
#endif
};

struct dp_pkt_mark {
	uint32_t id;
	struct {
		uint32_t is_recirc : 1;
	} flags;
	// check the init function if adding more,
	// due to this being small, memset has not been used
};

static_assert(sizeof(struct dp_flow) + sizeof(struct dp_pkt_mark) <= DP_MBUF_PRIV_DATA_SIZE,
			  "packet private data is too big to fit in packet");
static_assert((1 << (sizeof(((struct dp_flow *)0)->nxt_hop) * 8)) >= DP_MAX_PORTS,
			  "struct dp_flow::nxt_hop cannot hold all possible port_ids");
static_assert(sizeof(((struct dp_flow *)0)->vnf_type) == 1,
			  "enum dp_vnf_type is unnecessarily big");

extern rte_atomic32_t dp_pkt_id_counter;

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

	mark->id = rte_atomic32_add_return(&dp_pkt_id_counter, 1);
	mark->flags.is_recirc = false;
}


static __rte_always_inline void dp_extract_ipv4_header(struct dp_flow *df, const struct rte_ipv4_hdr *ipv4_hdr)
{
	df->src.src_addr = ipv4_hdr->src_addr;
	df->dst.dst_addr = ipv4_hdr->dst_addr;
	df->l4_type = ipv4_hdr->next_proto_id;
}

static __rte_always_inline void dp_extract_ipv6_header(struct dp_flow *df, const struct rte_ipv6_hdr *ipv6_hdr)
{
	rte_memcpy(df->dst.dst_addr6, ipv6_hdr->dst_addr, sizeof(df->dst.dst_addr6));
	rte_memcpy(df->src.src_addr6, ipv6_hdr->src_addr, sizeof(df->src.src_addr6));
	df->l4_type = ipv6_hdr->proto;
}

static __rte_always_inline int dp_extract_l4_header(struct dp_flow *df, const void *l4_hdr)
{
	if (df->l4_type == IPPROTO_TCP) {
		df->l4_info.trans_port.dst_port = ((const struct rte_tcp_hdr *)l4_hdr)->dst_port;
		df->l4_info.trans_port.src_port = ((const struct rte_tcp_hdr *)l4_hdr)->src_port;
		return DP_OK;
	} else if (df->l4_type == IPPROTO_UDP) {
		df->l4_info.trans_port.dst_port = ((const struct rte_udp_hdr *)l4_hdr)->dst_port;
		df->l4_info.trans_port.src_port = ((const struct rte_udp_hdr *)l4_hdr)->src_port;
		return DP_OK;
	} else if (df->l4_type == IPPROTO_ICMP) {
		df->l4_info.icmp_field.icmp_type = ((const struct rte_icmp_hdr *)l4_hdr)->icmp_type;
		df->l4_info.icmp_field.icmp_code = ((const struct rte_icmp_hdr *)l4_hdr)->icmp_code;
		df->l4_info.icmp_field.icmp_identifier = ((const struct rte_icmp_hdr *)l4_hdr)->icmp_ident;
		return DP_OK;
	} else if (df->l4_type == IPPROTO_ICMPV6) {
		df->l4_info.icmp_field.icmp_type = ((const struct rte_icmp_hdr *)l4_hdr)->icmp_type;
		return DP_OK;
	}

	return DP_ERROR;
}

static __rte_always_inline void dp_extract_underlay_header(struct dp_flow *df, const struct rte_ipv6_hdr *ipv6_hdr)
{
	rte_memcpy(df->tun_info.ul_src_addr6, ipv6_hdr->src_addr, sizeof(df->tun_info.ul_src_addr6));
	rte_memcpy(df->tun_info.ul_dst_addr6, ipv6_hdr->dst_addr, sizeof(df->tun_info.ul_dst_addr6));
	df->tun_info.proto_id = ipv6_hdr->proto;
}


static __rte_always_inline struct rte_ipv4_hdr *dp_get_ipv4_hdr(struct rte_mbuf *m)
{
	return rte_pktmbuf_mtod_offset(m, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
}

static __rte_always_inline struct rte_ipv6_hdr *dp_get_ipv6_hdr(struct rte_mbuf *m)
{
	return rte_pktmbuf_mtod_offset(m, struct rte_ipv6_hdr *, sizeof(struct rte_ether_hdr));
}

#ifdef __cplusplus
}
#endif
#endif
