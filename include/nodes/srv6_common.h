#ifndef __INCLUDE_SRV6_COMMON_H
#define __INCLUDE_SRV6_COMMON_H

#include "dpdk_layer.h"

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

};


// uint8_t get_sr6hdr_len (struct segment_routing6_hdr *sr6_hdr){
//     return 64 + sr6_hdr->hdr_ext_length;
// }

// void* serialize_sr6hdr(struct segment_routing6_hdr *sr6_hdr);
// struct segment_routing6_hdr* marshall_sr6hdr(struct segment_routing6_hdr *sr6_hdr);

#ifdef __cplusplus
}
#endif

#endif /* __INCLUDE_SRV6_COMMON_H */
