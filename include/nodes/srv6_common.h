#ifndef __INCLUDE_SRV6_COMMON_H
#define __INCLUDE_SRV6_COMMON_H

#include "dpdk_layer.h"
#include "rte_ip.h"

#ifdef __cplusplus
extern "C" {
#endif

struct segment6_item {

    uint8_t locator[8];
    uint8_t function[8];
//     struct segment6_item *next;
};

// struct segment_list{
//         uint8_t seg_addr_1[16];
// };


struct segment_routing_hdr {

    uint8_t next_hdr;
    uint8_t hdr_ext_length;
    uint8_t routing_type;
    uint8_t left_segments;
    uint8_t last_entry;
    uint8_t flags:8;
    uint16_t tag;
    
    struct segment6_item last_segment;
    // uint8_t last_segment[16];
    // struct segment6_item *segment_list;

} __rte_packed;

// This combined hdr is intended to bypass the current limitation of unsupported rte items: ipv6 with extension field, raw matching item for srv6 hdrd
//
struct srv6_combined_hdr{

    // struct rte_ipv6_hdr outter_ipv6_hdr;
    // struct segment_routing_hdr outter_srv6_hdr;
	
    rte_be32_t vtc_flow;	/**< IP version, traffic class & flow label. */ 
	rte_be16_t payload_len;	/**< IP payload size, including ext. headers */
	uint8_t  proto;		/**< Protocol, next header. */
	uint8_t  hop_limits;	/**< Hop limits. */
	uint8_t  src_addr[16];	/**< IP address of source host. */
	uint8_t  dst_addr[16];	/**< IP address of destination host(s). */


    uint8_t next_hdr;
    uint8_t hdr_ext_length;
    uint8_t routing_type;
    uint8_t left_segments;
    uint8_t last_entry;
    uint8_t flags:8;
    uint16_t tag;
    
    struct segment6_item last_segment;

} __rte_packed;


// struct srv6_hdr_fixed {

//     uint8_t next_hdr;
//     uint8_t hdr_ext_length;
//     uint8_t routing_type;
//     uint8_t left_segments;
//     uint8_t last_entry;
//     uint8_t flags:8;
//     uint16_t tag;
    
//     // struct segment6_item last_segment;
//     // uint8_t last_segment[16];
//     // struct segment6_item *segment_list;

// } __rte_packed;

// struct srv6_hdr_locator {

//     // uint8_t next_hdr;
//     // uint8_t hdr_ext_length;
//     // uint8_t routing_type;
//     // uint8_t left_segments;
//     // uint8_t last_entry;
//     // uint8_t flags:8;
//     // uint16_t tag;
    
//     uint8_t locator[8];
//     // uint8_t last_segment[16];
//     // struct segment6_item *segment_list;

// } __rte_packed;


// struct srv6_hdr_function {

//     // uint8_t next_hdr;
//     // uint8_t hdr_ext_length;
//     // uint8_t routing_type;
//     // uint8_t left_segments;
//     // uint8_t last_entry;
//     // uint8_t flags:8;
//     // uint16_t tag;
    
//     uint8_t function[8];
//     // uint8_t last_segment[16];
//     // struct segment6_item *segment_list;

// } __rte_packed;



// uint8_t get_sr6hdr_len (struct segment_routing6_hdr *sr6_hdr){
//     return 64 + sr6_hdr->hdr_ext_length;
// }

// void* serialize_sr6hdr(struct segment_routing6_hdr *sr6_hdr);
// struct segment_routing6_hdr* marshall_sr6hdr(struct segment_routing6_hdr *sr6_hdr);

#ifdef __cplusplus
}
#endif

#endif /* __INCLUDE_SRV6_COMMON_H */
