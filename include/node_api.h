#ifndef __PUBLIC_API_H__
#define __PUBLIC_API_H__

#include <rte_common.h>
#include <rte_flow.h>
#include "dp_flow.h"

#ifdef __cplusplus
extern "C" {
#endif

struct dp_flow {
	struct {
		uint8_t	flow_type : 2;		// local,outgoing,incoming
		uint8_t public_flow : 1;    
		uint8_t	overlay_type: 1;	// supported overlay type
		uint8_t	valid : 1;			// maybe change to offload to indicate if this flow needs to offloaded
		uint8_t	nat : 3;
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
	
	uint8_t					l4_type;
	uint16_t				dst_port;
	uint16_t				src_port;
	
	uint8_t					icmp_type;
	uint32_t                dp_flow_hash;

	struct {
		uint8_t		ul_src_addr6[16];
		uint8_t		ul_dst_addr6[16];
		uint16_t 	l3_type;	//layer-3 type in ethernet header of outter packets
		uint8_t		proto_id;	//proto_id in outter ipv6 header
		uint16_t	src_port;	//src_port in outter udp header
		uint16_t	dst_port;	//dst_port in outter udp header
		uint32_t	dst_vni;
	} tun_info;
	uint8_t				nxt_hop;
	uint8_t				periodic_type;
	struct flow_value	*conntrack;
};

struct dp_mbuf_priv1 {
	struct dp_flow *flow_ptr;
};

typedef enum {
 	DP_PER_TYPE_ND_RA,
 	DP_PER_TYPE_DIRECT_TX,
 } dp_periodic_type;

#ifdef __cplusplus
}
#endif

#endif
