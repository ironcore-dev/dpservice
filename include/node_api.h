#ifndef __PUBLIC_API_H__
#define __PUBLIC_API_H__

#include <rte_common.h>
#include <rte_flow.h>

#ifdef __cplusplus
extern "C" {
#endif

struct dp_flow {
	uint64_t				ul_dst_addr6[2];
	union {
		uint32_t				dst_addr;
		uint8_t					dst_addr6[16];
	} dst;
	union {
		uint32_t				src_addr;
		uint8_t					src_addr6[16];
	} src;
	uint32_t				dst_vni;
	uint16_t				dst_port;
	uint16_t				src_port;
	uint8_t					nxt_hop;
	uint16_t 				l3_type;
	uint8_t					l4_type;
	uint8_t					icmp_type;
	uint8_t					periodic_type;
	struct {
		uint8_t				geneve_hdr : 1;
		uint8_t				valid : 1;
		uint8_t				nat : 2;
	} flags;
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
