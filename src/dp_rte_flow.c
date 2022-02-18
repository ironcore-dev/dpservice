#include "dp_rte_flow.h"
#include "dp_flow.h"
#include "dp_lpm.h"
#include "nodes/dhcp_node.h"
#include "node_api.h"
#include "nodes/srv6_common.h"
#include "nodes/ipv6_nd_node.h"

const static uint8_t ether_addr_mask[RTE_ETHER_ADDR_LEN]="\xff\xff\xff\xff\xff\xff";
const static uint8_t ipv6_addr_mask[16] = "\xff\xff\xff\xff\xff\xff\xff\xff"
						   "\xff\xff\xff\xff\xff\xff\xff\xff";

uint16_t extract_inner_ethernet_header(struct rte_mbuf* pkt){
    
    struct rte_ether_hdr *eth_hdr;
    struct dp_flow *df;

    df=get_dp_flow_ptr(pkt);

    if (df == NULL){
         printf("NULL df \n");
    }
   
    eth_hdr = rte_pktmbuf_mtod(pkt,struct rte_ether_hdr * );
    df->l3_type=ntohs(eth_hdr->ether_type);

    // mac address can be also extracted here, but I don't need them now

    return df->l3_type;
}

uint16_t extract_outter_ethernet_header(struct rte_mbuf* pkt){
    
    struct rte_ether_hdr *eth_hdr;
    struct dp_flow *df;

    df=get_dp_flow_ptr(pkt);

    if (df == NULL){
         printf("NULL df \n");
    }
   
    eth_hdr = rte_pktmbuf_mtod(pkt,struct rte_ether_hdr * );
    df->tun_info.l3_type=ntohs(eth_hdr->ether_type);

    // mac address can be also extracted here, but I don't need them now

    return df->l3_type;
}

int extract_inner_l3_header(struct rte_mbuf* pkt,void* hdr,uint16_t offset){
    struct dp_flow *df;
    struct rte_ipv4_hdr *ipv4_hdr;
    struct rte_ipv6_hdr *ipv6_hdr;

    df=get_dp_flow_ptr(pkt);
    if (df->l3_type==RTE_ETHER_TYPE_IPV4){
        if (hdr != NULL){
            ipv4_hdr=(struct rte_ipv4_hdr*)hdr;
        }else{
            ipv4_hdr=rte_pktmbuf_mtod_offset(pkt,struct rte_ipv4_hdr*,offset);
        }

        df->src.src_addr=ipv4_hdr->src_addr;
        df->dst.dst_addr=ipv4_hdr->dst_addr;
        df->l4_type = ipv4_hdr->next_proto_id;
        // printf("extract for ipv4 header, protoid is %#x \n",ipv4_hdr->next_proto_id);
        return df->l4_type;

    }else if (df->l3_type==RTE_ETHER_TYPE_IPV6){
        if (hdr != NULL){
            ipv6_hdr=(struct rte_ipv6_hdr*)hdr;
        }else{
            ipv6_hdr=rte_pktmbuf_mtod_offset(pkt,struct rte_ipv6_hdr*,offset);
        }

        rte_memcpy(df->dst.dst_addr6, ipv6_hdr->dst_addr,sizeof(df->dst.dst_addr6));
	    rte_memcpy(df->src.src_addr6, ipv6_hdr->src_addr,sizeof(df->src.src_addr6));
        df->l4_type = ipv6_hdr->proto;
        return df->l4_type;
    }

    return -1;
}

int extract_inner_l4_header(struct rte_mbuf* pkt,void* hdr,uint16_t offset){

     struct dp_flow *df;
     struct rte_tcp_hdr *tcp_hdr;
     struct rte_udp_hdr *udp_hdr;     
    
     struct rte_icmp_hdr *icmp_hdr;
     struct icmp6hdr *icmp6_hdr;

    df=get_dp_flow_ptr(pkt);
    if (df->l4_type == DP_IP_PROTO_TCP) {
        if (hdr != NULL){
            tcp_hdr=(struct rte_tcp_hdr*)hdr;
        }else{
            tcp_hdr=rte_pktmbuf_mtod_offset(pkt,struct rte_tcp_hdr*,offset);
        }
		df->dst_port = tcp_hdr->dst_port;
		df->src_port = tcp_hdr->src_port;
        return 0;
        
	} else if (df->l4_type== DP_IP_PROTO_UDP) {
		if (hdr != NULL){
            udp_hdr=(struct rte_udp_hdr*)hdr;
        }else{
            udp_hdr=rte_pktmbuf_mtod_offset(pkt,struct rte_udp_hdr*,offset);
        }
		df->dst_port = udp_hdr->dst_port;
		df->src_port = udp_hdr->src_port;
        return 0;
	} else if (df->l4_type == DP_IP_PROTO_ICMP) {
		if (hdr != NULL){
            icmp_hdr=(struct rte_icmp_hdr*)hdr;
        }else{
            icmp_hdr=rte_pktmbuf_mtod_offset(pkt,struct rte_icmp_hdr*,offset);
        }
		df->icmp_type = icmp_hdr->icmp_type;
        return 0;
	}else if (df->l4_type==DP_IP_PROTO_ICMPV6){
        if (hdr != NULL){
            icmp6_hdr=(struct icmp6hdr*)hdr;
        }else{
            icmp6_hdr=rte_pktmbuf_mtod_offset(pkt,struct icmp6hdr*,offset);
        }
		df->icmp_type = icmp6_hdr->icmp6_type;
        return 0;
    }

    return -1;

}

// int extract_inner_l3_l4_header(struct rte_mbuf* pkt,uint16_t offset); //call the above two functions

int extract_outer_ipv6_header(struct rte_mbuf* pkt,void* hdr,uint16_t offset){

    struct dp_flow *df;
    struct rte_ipv6_hdr *ipv6_hdr=NULL;

    df=get_dp_flow_ptr(pkt);

	if (hdr != NULL){
            ipv6_hdr=(struct rte_ipv6_hdr*)hdr;
        }else{
            ipv6_hdr=rte_pktmbuf_mtod_offset(pkt,struct rte_ipv6_hdr*,offset);
        }

    if (ipv6_hdr!=NULL){
        rte_memcpy(df->tun_info.ul_src_addr6,ipv6_hdr->src_addr,sizeof(df->tun_info.ul_src_addr6));
        rte_memcpy(df->tun_info.ul_dst_addr6,ipv6_hdr->dst_addr,sizeof(df->tun_info.ul_dst_addr6));
        df->tun_info.proto_id=ipv6_hdr->proto;
        // printf("ipv6->proto %#x \n",ipv6_hdr->proto);
        // printf("ipv6->hop_limits %#x \n",ipv6_hdr->hop_limits);
        // printf("payload length in arriving ipv6 hdr %#x \n",ipv6_hdr->payload_len);
        return ipv6_hdr->proto;
    }

    return -1;

}

int extract_outer_srv6_header(struct rte_mbuf* pkt,void* hdr,uint16_t offset){
     
     struct dp_flow *df;
     struct segment_routing_hdr *seg_hdr;

      df=get_dp_flow_ptr(pkt);

      	if (hdr != NULL){
            seg_hdr=(struct segment_routing_hdr*)hdr;
        }else{
            seg_hdr=rte_pktmbuf_mtod_offset(pkt,struct segment_routing_hdr*,offset);
        }

    memcpy(&df->tun_info.dst_vni,seg_hdr->last_segment.function,4);
	if (seg_hdr->next_hdr==DP_IP_PROTO_IPv4_ENCAP){
		df->l3_type=RTE_ETHER_TYPE_IPV4;
        return df->l3_type;
	}

    return -1;

}


void create_rte_flow_rule_attr (struct rte_flow_attr *attr, uint32_t group, uint32_t priority,uint32_t ingress, uint32_t egress, uint32_t transfer){

    memset(attr,0, sizeof(struct rte_flow_attr));
    
    attr->group=group;
    attr->ingress=ingress;
    attr->egress=egress;
    attr->priority=priority;
    attr->transfer=transfer;

}
int insert_ethernet_match_pattern(struct rte_flow_item *pattern,int pattern_cnt, 
                                struct rte_flow_item_eth *eth_spec,
	                            struct rte_flow_item_eth *eth_mask,
                                struct rte_ether_addr *src, size_t nr_src_mask_len,
                                struct rte_ether_addr *dst, size_t nr_dst_mask_len,
                                rte_be16_t type){

    memset(eth_spec, 0, sizeof(struct rte_flow_item_eth));
	memset(eth_mask, 0, sizeof(struct rte_flow_item_eth));

    if (src){
        memcpy(&(eth_spec->src),src,nr_src_mask_len);
        memcpy(&(eth_mask->src),ether_addr_mask,nr_src_mask_len);
    }

    if (dst){
        memcpy(&(eth_spec->src),src,nr_dst_mask_len);
        memcpy(&(eth_mask->src),ether_addr_mask,nr_dst_mask_len);
    }

    eth_spec->type = type;
	eth_mask->type = htons(0xffff);
    
    pattern[pattern_cnt].type = RTE_FLOW_ITEM_TYPE_ETH;
    pattern[pattern_cnt].spec = eth_spec;
	pattern[pattern_cnt].mask = eth_mask;

    return pattern_cnt++;

}


int insert_ipv6_match_pattern(struct rte_flow_item *pattern,int pattern_cnt, 
                            struct rte_flow_item_ipv6 *ipv6_spec,
	                        struct rte_flow_item_ipv6 *ipv6_mask,
                            uint8_t *src, size_t nr_src_mask_len,
                            uint8_t *dst, size_t nr_dst_mask_len,
                            uint8_t proto){


    memset(ipv6_spec, 0, sizeof(struct rte_flow_item_ipv6));
	memset(ipv6_mask, 0, sizeof(struct rte_flow_item_ipv6));

    if (src){
        memcpy(ipv6_spec->hdr.src_addr,src,nr_src_mask_len);
        memcpy(ipv6_mask->hdr.src_addr,ipv6_addr_mask,nr_src_mask_len);
    }

    if (dst){
        memcpy(ipv6_spec->hdr.dst_addr,dst,nr_dst_mask_len);
        memcpy(ipv6_mask->hdr.dst_addr,ipv6_addr_mask,nr_dst_mask_len);
    }

    ipv6_spec->hdr.proto=proto;
    ipv6_mask->hdr.proto = 0xff;

    pattern[pattern_cnt].type = RTE_FLOW_ITEM_TYPE_IPV6;
    pattern[pattern_cnt].spec = ipv6_spec;
	pattern[pattern_cnt].mask = ipv6_mask;

    return pattern_cnt++;
}


//TODO: remove these srv6 related testing code

// struct rte_flow_item_flex_field field0 = {
//         .field_mode = FIELD_MODE_FIXED,
//         .field_size =  8 * sizeof(struct srv6_combined_hdr),
//         .field_base = 0,
//   };


// struct rte_flow_item_eth flex_eth_spec ={
//     .hdr = {
//         .ether_type=RTE_BE16(RTE_ETHER_TYPE_IPV6),
//     },
//         // .type=RTE_ETHER_TYPE_IPV6,
// };
// struct rte_flow_item_eth flex_eth_mask={

//         .hdr = {
//         .ether_type=RTE_BE16(0xffff),
//     },

// };

// struct rte_flow_item_flex_link flex_input_link_eth = {
//     .item = {
//        .type = RTE_FLOW_ITEM_TYPE_ETH,
//        .spec = &flex_eth_spec,
//        .mask = &flex_eth_mask,
//     },
//   };

// struct rte_flow_item_flex_link flex_output_link_ipv4 = {
//     .item = {
//        .type = RTE_FLOW_ITEM_TYPE_IPV4,
//     },
//     .next = RTE_BE16(DP_IP_PROTO_IPv4_ENCAP),
//   };
// struct rte_flow_item_flex_link flex_output_link_ipv6 = {
//     .item = {
//        .type = RTE_FLOW_ITEM_TYPE_IPV6,
//     },
//     .next = RTE_BE16(DP_IP_PROTO_IPv6_ENCAP),
//   };


// // // Use rte_flow_item_flex to match ipv6+srv6 header since rte_flow_item_raw, and rte_flow_item_ipv6 have limitations
// const struct rte_flow_item_flex_conf srv6_flex_conf = {

//     .tunnel = FLEX_TUNNEL_MODE_TUNNEL,

//     .next_header = {
//         .field_mode = FIELD_MODE_FIXED,
//         .field_size = 8 * sizeof(struct srv6_combined_hdr),
//     },

//     .next_protocol = {
//         .field_mode = FIELD_MODE_FIXED,
//         .field_base = 8 * sizeof(struct rte_ipv6_hdr),
//         .field_size = 8,
//     },

//     .sample_data = {
//         &field0,
//     },
//     .nb_samples =1,

//     .input_link={
//         &flex_input_link_eth,
//     },
//     .nb_inputs=1,

//     .output_link = {
//         &flex_output_link_ipv4,
//         &flex_output_link_ipv6,
//     },
//     .nb_outputs=2,

// };

// struct rte_flow_item_flex_field field10 = {
//         .field_mode = FIELD_MODE_FIXED,
//         // .field_size = 4 * sizeof(char) * CHAR_BIT,
//         .field_size = 2,
//         .field_base = 0,
//   };

// const struct rte_flow_item_flex_conf ecpri_flex_conf = {
//       /* single eCPRI header in a packet. Can be ether inner or outer */
//       .tunnel = FLEX_TUNNEL_MODE_SINGLE,

//       /* eCPRI header size description */
//       .next_header = {
//         .field_mode = FIELD_MODE_FIXED,  /* fixed-size header */
//         //  .field_size = 4 * sizeof(char) * CHAR_BIT,
//          .field_size = 2,
//       },

//       /* eCPRI header is followed by a payload */
//       .next_protocol = {},

//       /* single sample that covers entire eCPRI header */
//       .sample_data = {
//          &field10,
//       },
//       .nb_samples = 1,

//       /* eCPRI protocol follows ether Ethernet or UDP headers */
//       .input_link = {
//            &flex_input_link_eth,
//         //  {
//         //     .item = {
//         //        .type = RTE_FLOW_ITEM_TYPE_ETH,
//         //        .spec = &(struct rte_flow_item_eth) {
//         //           .type = RTE_BE16(0xAEFE),
//         //        },
//         //     }
//         //  },
//         //  {
//         //     .item = {
//         //        .type = RTE_FLOW_ITEM_TYPE_UDP,
//         //        .spec = &(struct rte_flow_item_udp) {
//         //           .hdr.dst_port = RTE_BE16(0xAEFE)
//         //        },
//         //     }
//         //  },
//       },
//       .nb_inputs = 1,

//       /* no network protocol follows eCPRI header */
//       .nb_outputs = 0,
//    };

 
// New tests
// struct rte_flow_item_flex_field field0 = {
//         .field_mode = FIELD_MODE_FIXED,
//         .field_size =  8 * sizeof(struct srv6_hdr_fixed),
//         .field_base = 0,
//   };

// struct rte_flow_item_flex_field field1 = {
//         .field_mode = FIELD_MODE_FIXED,
//         .field_size =  8 * sizeof(struct srv6_hdr_locator),
//         .field_base = 0,
//   };

// struct rte_flow_item_flex_field field2 = {
//         .field_mode = FIELD_MODE_FIXED,
//         .field_size =  8 * sizeof(struct srv6_hdr_function),
//         .field_base = 0,
//   };


// struct rte_flow_item_eth flex_eth_spec ={
//     .hdr = {
//         .ether_type=RTE_BE16(RTE_ETHER_TYPE_IPV6),
//     },
//         // .type=RTE_ETHER_TYPE_IPV6,
// };
// struct rte_flow_item_eth flex_eth_mask={

//         .hdr = {
//         .ether_type=RTE_BE16(0xffff),
//     },

// };

// struct rte_flow_item_flex_link flex_input_link_eth = {
//     .item = {
//        .type = RTE_FLOW_ITEM_TYPE_ETH,
//        .spec = &flex_eth_spec,
//        .mask = &flex_eth_mask,
//     },
//   };

// struct rte_flow_item_flex_link flex_output_link_ipv4 = {
//     .item = {
//        .type = RTE_FLOW_ITEM_TYPE_IPV4,
//     },
//     .next = RTE_BE16(DP_IP_PROTO_IPv4_ENCAP),
//   };
// struct rte_flow_item_flex_link flex_output_link_ipv6 = {
//     .item = {
//        .type = RTE_FLOW_ITEM_TYPE_IPV6,
//     },
//     .next = RTE_BE16(DP_IP_PROTO_IPv6_ENCAP),
//   };


// // Use rte_flow_item_flex to match ipv6+srv6 header since rte_flow_item_raw, and rte_flow_item_ipv6 have limitations
// const struct rte_flow_item_flex_conf srv6_fixed_flex_conf = {

//     .tunnel = FLEX_TUNNEL_MODE_TUNNEL,

//     .next_header = {
//         .field_mode = FIELD_MODE_FIXED,
//         .field_size = 8 * sizeof(struct srv6_hdr_fixed),
//     },

//     .next_protocol = {
//         // .field_base = 8 * sizeof(struct rte_ipv6_hdr),
//         // .field_size = 8,
//     },

//     .sample_data = {
//         &field0,
//     },
//     .nb_samples =1,

//     .input_link={
//         &flex_input_link_eth,
//     },
//     .nb_inputs=1,

//     // .output_link = {
//     //     // &flex_output_link_ipv4,
//     //     // &flex_output_link_ipv6,
//     // },
//     .nb_outputs=0,
// };

// const struct rte_flow_item_flex_conf srv6_locator_flex_conf = {

//     .tunnel = FLEX_TUNNEL_MODE_TUNNEL,

//     .next_header = {
//         .field_mode = FIELD_MODE_FIXED,
//         .field_size = 8 * sizeof(struct srv6_hdr_locator),
//     },

//     .next_protocol = {
//         // .field_base = 8 * sizeof(struct rte_ipv6_hdr),
//         // .field_size = 8,
//     },

//     .sample_data = {
//         &field1,
//     },
//     .nb_samples =1,

//     .input_link={
//         &flex_input_link_eth,
//     },
//     .nb_inputs=1,

//     // .output_link = {
//     //     // &flex_output_link_ipv4,
//     //     // &flex_output_link_ipv6,
//     // },
//     .nb_outputs=0,
// };

// int craft_srv6_pattern_combined_hdr(struct rte_flow_item *pattern,
//                                     uint16_t port_id,
//                                     struct rte_ipv6_hdr *ipv6_hdr, 
//                                     struct segment_routing_hdr *srv6_hdr){
//      struct rte_flow_item_flex_handle *srv6_fixed_flex_handle;
//      struct rte_flow_error error;

//      uint8_t	dst_addr[16] = "\xff\xff\xff\xff\xff\xff\xff\xff"
// 						   "\xff\xff\xff\xff\xff\xff\xff\xff";
    
//     srv6_fixed_flex_handle = rte_flow_flex_item_create(port_id,&srv6_fixed_flex_conf,&error);
     
//      if (srv6_fixed_flex_handle==NULL){
// 		printf("Flex item cannot be created: %s\n", error.message ? error.message : "(no stated reason)");
//         return 0;
//      }

//     struct srv6_hdr_fixed srv6_hdr_fixed_spec;
//     struct srv6_hdr_fixed srv6_hdr_fixed_mask;

//     memset(&srv6_hdr_fixed_spec,0, sizeof(struct srv6_hdr_fixed));
//     memset(&srv6_hdr_fixed_mask,0, sizeof(struct srv6_hdr_fixed));
//      //     // match srv6 hdr fields
// //     memcpy(&concatenated_hdr_spec.last_segment,&(srv6_hdr->last_segment),sizeof(concatenated_hdr_spec.last_segment));
// //     memcpy(&concatenated_hdr_mask.last_segment,dst_addr,sizeof(concatenated_hdr_mask.last_segment));

// //     struct rte_flow_item_flex srv6_flex_item_spec = {
// //         .handle=srv6_flex_handle,
// //         .length=sizeof(concatenated_hdr_spec),
// //         .pattern=&concatenated_hdr_spec,
// //     };
// //     struct rte_flow_item_flex srv6_flex_item_mask = {
// //         .handle=srv6_flex_handle,
// //         .length=sizeof(concatenated_hdr_mask),
// //         .pattern=&concatenated_hdr_mask,
// //     };


// }

// struct rte_flow_item_flex_handle *srv6_flex_handle=NULL;
// int craft_srv6_pattern_combined_hdr(struct rte_flow_item *pattern,
//                                     uint16_t port_id,
//                                     struct rte_ipv6_hdr *ipv6_hdr, 
//                                     struct segment_routing_hdr *srv6_hdr){

//      struct rte_flow_item_flex_handle *srv6_flex_handle;
//      struct rte_flow_error error;

// //     struct rte_flow_item_flex_handle *ecpri_flex_handle;
// //     ecpri_flex_handle = rte_flow_flex_item_create(port_id, &ecpri_flex_conf,&error);
// //    if (ecpri_flex_handle==NULL){
// //        	printf("Flex item cannot be created: %s\n", error.message ? error.message : "(no stated reason)");
// //         return 0;
// //    }
//         srv6_flex_handle = rte_flow_flex_item_create(port_id,&srv6_flex_conf,&error);
//    // TODO: put it somewhere in header file and use it across .c files
//      uint8_t	dst_addr[16] = "\xff\xff\xff\xff\xff\xff\xff\xff"
// 						   "\xff\xff\xff\xff\xff\xff\xff\xff";
     
//      //TODO: figure out if it is ok to create flex item for each new flow, or the release 
//      // function needs to be called after the flow is installed.
//      if (srv6_flex_handle==NULL)
//         srv6_flex_handle = rte_flow_flex_item_create(port_id,&srv6_flex_conf,&error);
     
//      if (srv6_flex_handle==NULL){
// 		printf("Flex item cannot be created: %s\n", error.message ? error.message : "(no stated reason)");
//         return 0;
//      }

//     struct srv6_combined_hdr concatenated_hdr_spec;
//     struct srv6_combined_hdr concatenated_hdr_mask;

//     //init
//     memset(&concatenated_hdr_spec,0, sizeof(struct srv6_combined_hdr));
//     memset(&concatenated_hdr_mask,0, sizeof(struct srv6_combined_hdr));

//     // match ipv6 fields
//     memcpy(&concatenated_hdr_spec.proto,&(ipv6_hdr->proto),sizeof(uint8_t));
//     memcpy(&concatenated_hdr_spec.dst_addr,ipv6_hdr->dst_addr,sizeof(concatenated_hdr_spec.dst_addr));

//     concatenated_hdr_mask.proto=0xff;
//     memcpy(&concatenated_hdr_mask.dst_addr,dst_addr,sizeof(concatenated_hdr_mask.dst_addr));

//     // match srv6 hdr fields
//     memcpy(&concatenated_hdr_spec.last_segment,&(srv6_hdr->last_segment),sizeof(concatenated_hdr_spec.last_segment));
//     memcpy(&concatenated_hdr_mask.last_segment,dst_addr,sizeof(concatenated_hdr_mask.last_segment));

//     struct rte_flow_item_flex srv6_flex_item_spec = {
//         .handle=srv6_flex_handle,
//         .length=sizeof(concatenated_hdr_spec),
//         .pattern=&concatenated_hdr_spec,
//     };
//     struct rte_flow_item_flex srv6_flex_item_mask = {
//         .handle=srv6_flex_handle,
//         .length=sizeof(concatenated_hdr_mask),
//         .pattern=&concatenated_hdr_mask,
//     };

//     pattern->type = RTE_FLOW_ITEM_TYPE_FLEX;
//     pattern->spec=&srv6_flex_item_spec;
//     pattern->mask=&srv6_flex_item_mask;


//     return pattern->type;
// }



