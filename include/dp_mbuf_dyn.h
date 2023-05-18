#ifndef __INCLUDE_DP_MBUF_DYN_H__
#define __INCLUDE_DP_MBUF_DYN_H__

#include <rte_common.h>
#include <rte_flow.h>
#include "dp_flow.h"

#ifdef ENABLE_VIRTSVC
#	include "dp_virtsvc.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

struct dp_flow {
	struct {
		uint8_t	flow_type : 2;		// local,outgoing,incoming
		uint8_t public_flow : 1;
		uint8_t	overlay_type: 1;	// supported overlay type
		uint8_t	nat : 3;
		uint8_t offload_ipv6 : 1;	// tmp solution to set if we should offload ipv6 pkts
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
	uint8_t				vnf_type;
	// TODO(plague): port_id is uint16_t though, theoretically this is too little
	uint8_t				nxt_hop;
	uint8_t				periodic_type;
	union {
		struct flow_value	*conntrack;
#ifdef ENABLE_VIRTSVC
		struct dp_virtsvc	*virtsvc;
#endif
	};
};

// not used in dp_flow instead of uint8_t
// due to enums being int-sized
enum dp_periodic_type{
	DP_PER_TYPE_ZERO,
	DP_PER_TYPE_ND_RA,
	DP_PER_TYPE_DIRECT_TX,
};

struct dp_flow *get_dp_flow_ptr(struct rte_mbuf *m);
struct dp_flow *init_dp_flow_ptr(struct rte_mbuf *m);

#ifdef __cplusplus
}
#endif
#endif
