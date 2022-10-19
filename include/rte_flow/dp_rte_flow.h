#ifndef __INCLUDE_DP_RTE_FLOW_H
#define __INCLUDE_DP_RTE_FLOW_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_flow.h>
#include "dp_mbuf_dyn.h"

#include "dp_lpm.h"

#include "node_api.h"

#define DP_FLOW_TYPE_LOCAL		1
#define DP_FLOW_TYPE_OUTGOING	2
#define DP_FLOW_TYPE_INCOMING	3

#define DP_FLOW_WEST_EAST		0
#define DP_FLOW_SOUTH_NORTH		1

#define DP_FLOW_OVERLAY_TYPE_IPIP	0
#define DP_FLOW_OVERLAY_TYPE_GENEVE	1

#define DP_IS_SRC false
#define DP_IS_DST true

#define DP_L4_PORT_DIR_SRC 1
#define DP_L4_PORT_DIR_DST 2


// #define DP_RTE_FLOW_DEFAULT_GROUP	0
// #define DP_RTE_FLOW_VNET_GROUP		1

uint16_t extract_inner_ethernet_header(struct rte_mbuf *pkt);
uint16_t extract_outter_ethernet_header(struct rte_mbuf *pkt);
int extract_inner_l3_header(struct rte_mbuf *pkt, void *hdr, uint16_t offset); // offset, ipv4/ipv6 header
int extract_inner_l4_header(struct rte_mbuf *pkt, void *hdr, uint16_t offset); // offset,  tcp/udp/icmp header
int extract_outer_ipv6_header(struct rte_mbuf *pkt, void *hdr, uint16_t offset);
struct rte_ipv4_hdr *dp_get_ipv4_hdr(struct rte_mbuf *m);
struct rte_tcp_hdr *dp_get_tcp_hdr(struct rte_mbuf *m, uint16_t offset);
struct rte_udp_hdr *dp_get_udp_hdr(struct rte_mbuf *m, uint16_t offset);

uint16_t dp_change_l4_hdr_port(struct rte_mbuf *m, uint8_t port_type, uint16_t new_val);

// functions to craft actions/patterns are added later
void create_rte_flow_rule_attr(struct rte_flow_attr *attr, uint32_t group, uint32_t priority, uint32_t ingress, uint32_t egress, uint32_t transfer);

int insert_ethernet_match_pattern(struct rte_flow_item *pattern, int pattern_cnt,
									struct rte_flow_item_eth *eth_spec,
									struct rte_flow_item_eth *eth_mask,
									struct rte_ether_addr *src, size_t nr_src_mask_len,
									struct rte_ether_addr *dst, size_t nr_dst_mask_len,
									rte_be16_t type);

int insert_ipv6_match_pattern(struct rte_flow_item *pattern, int pattern_cnt,
								struct rte_flow_item_ipv6 *ipv6_spec,
								struct rte_flow_item_ipv6 *ipv6_mask,
								uint8_t *src, size_t nr_src_mask_len,
								uint8_t *dst, size_t nr_dst_mask_len,
								uint8_t proto);

int insert_ipv4_match_pattern(struct rte_flow_item *pattern, int pattern_cnt,
							  struct rte_flow_item_ipv4 *ipv4_spec,
							  struct rte_flow_item_ipv4 *ipv4_mask,
							  struct dp_flow *df, bool dir);

int insert_udp_match_pattern(struct rte_flow_item *pattern, int pattern_cnt,
								struct rte_flow_item_udp *udp_spec,
								struct rte_flow_item_udp *udp_mask,
								uint16_t src_port, uint16_t dst_port);

int insert_tcp_match_pattern(struct rte_flow_item *pattern, int pattern_cnt,
								struct rte_flow_item_tcp *tcp_spec,
								struct rte_flow_item_tcp *tcp_mask,
								uint16_t src_port, uint16_t dst_port);

int insert_icmp_match_pattern(struct rte_flow_item *pattern, int pattern_cnt,
								struct rte_flow_item_icmp *icmp_spec,
								struct rte_flow_item_icmp *icmp_mask,
								uint8_t type);

int insert_icmpv6_match_pattern(struct rte_flow_item *pattern, int pattern_cnt,
								struct rte_flow_item_icmp6 *icmp6_spec,
								struct rte_flow_item_icmp6 *icmp6_mask,
								uint8_t type);

int insert_geneve_match_pattern(struct rte_flow_item *pattern, int pattern_cnt,
								struct rte_flow_item_geneve *geneve_spec,
								struct rte_flow_item_geneve *geneve_mask,
								uint16_t type, uint32_t *vni);

int insert_packet_mark_match_pattern(struct rte_flow_item *pattern, int pattern_cnt,
									struct rte_flow_item_mark *mark_spec,
									struct rte_flow_item_mark *mark_mask,
									uint32_t marked_id);

int insert_tag_match_pattern(struct rte_flow_item *pattern, int pattern_cnt,
									struct rte_flow_item_tag *tag_spec,
									struct rte_flow_item_tag *tag_mask,
									uint32_t tag_value, uint8_t tag_index);

int insert_meta_match_pattern(struct rte_flow_item *pattern, int pattern_cnt,
							struct rte_flow_item_meta *meta_spec,
							struct rte_flow_item_meta *meta_mask,
							uint32_t meta_value);

int insert_end_match_pattern(struct rte_flow_item *pattern, int pattern_cnt);


int create_raw_decap_action(struct rte_flow_action *action, int action_cnt,
							struct rte_flow_action_raw_decap *raw_decap_action,
							uint8_t *data_to_decap, size_t data_len);

int create_raw_encap_action(struct rte_flow_action *action, int action_cnt,
							struct rte_flow_action_raw_encap *raw_encap_action,
							uint8_t *data_to_encap, size_t data_len);

int create_dst_mac_set_action(struct rte_flow_action *action, int action_cnt,
							  struct rte_flow_action_set_mac *dst_mac_set_action,
							  struct rte_ether_addr *dst_mac);

int create_src_mac_set_action(struct rte_flow_action *action, int action_cnt,
							  struct rte_flow_action_set_mac *src_mac_set_action,
							  struct rte_ether_addr *src_mac);

int create_ipv4_set_action(struct rte_flow_action *action, int action_cnt,
						   struct rte_flow_action_set_ipv4 *ipv4_action,
						   uint32_t ipv4, bool dir);

int create_send_to_port_action(struct rte_flow_action *action, int action_cnt,
								struct rte_flow_action_port_id *send_to_port_action,
								uint32_t port_id);

int create_flow_age_action(struct rte_flow_action *action, int action_cnt,
							struct rte_flow_action_age *flow_age_action,
							uint32_t timeout, void *age_context);

void free_allocated_agectx(struct flow_age_ctx *agectx);

void config_allocated_agectx(struct flow_age_ctx *agectx, uint16_t port_id,
								struct dp_flow *df, struct rte_flow *flow);

int create_redirect_queue_action(struct rte_flow_action *action, int action_cnt,
									struct rte_flow_action_queue *queue_action,
									uint16_t queue_index);

int create_packet_mark_action(struct rte_flow_action *action, int action_cnt,
							struct rte_flow_action_mark *mark_action,
							uint32_t marked_value);

int create_set_tag_action(struct rte_flow_action *action, int action_cnt,
							struct rte_flow_action_set_tag *set_tag_action,
							uint32_t tag_value, uint8_t index);

int create_set_meta_action(struct rte_flow_action *action, int action_cnt,
							struct rte_flow_action_set_meta *meta_action,
							uint32_t meta_value);

int create_end_action(struct rte_flow_action *action, int action_cnt);

struct rte_flow *validate_and_install_rte_flow(uint16_t port_id,
												const struct rte_flow_attr *attr,
												const struct rte_flow_item pattern[],
												const struct rte_flow_action action[],
												struct dp_flow *df);

#ifdef __cplusplus
}
#endif

#endif /* __INCLUDE_DP_RTE_FLOW_H */
