#ifndef __PUBLIC_API_H__
#define __PUBLIC_API_H__

#include <rte_common.h>
#include <rte_flow.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DP_MAX_PATT_ACT	4

struct dp_flow {
	struct rte_flow_attr	attr;
	struct rte_flow_item	pattern[DP_MAX_PATT_ACT];
	struct rte_flow_action	action[DP_MAX_PATT_ACT];
	uint8_t					pattern_cnt;
	uint8_t					action_cnt;
	uint8_t					valid;
	uint8_t					nxt_hop;
	uint16_t				dst_port;
	uint16_t				src_port;
	uint32_t				dst_addr;
	uint32_t				src_addr;
	uint8_t					l4_type;
	uint8_t					icmp_type;
};

struct dp_mbuf_priv1 {
	struct dp_flow *flow_ptr;
};

#ifdef __cplusplus
}
#endif

#endif
