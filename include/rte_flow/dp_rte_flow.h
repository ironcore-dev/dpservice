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

#include "dp_log.h"
#include "dp_lpm.h"
#include "dp_mbuf_dyn.h"

#define DP_FLOW_TYPE_LOCAL		1
#define DP_FLOW_TYPE_OUTGOING	2
#define DP_FLOW_TYPE_INCOMING	3

#define DP_FLOW_WEST_EAST		0
#define DP_FLOW_SOUTH_NORTH		1

#define DP_L4_PORT_DIR_SRC 1
#define DP_L4_PORT_DIR_DST 2

#define DP_IP_ICMP_TYPE_ERROR 3

#define DP_IP_ICMP_CODE_DST_PROTO_UNREACHABLE 2
#define DP_IP_ICMP_CODE_DST_PORT_UNREACHABLE 3
#define DP_IP_ICMP_CODE_FRAGMENT_NEEDED 4

#define DP_TCP_CONTROL_FLAGS \
	(RTE_TCP_FIN_FLAG|RTE_TCP_SYN_FLAG|RTE_TCP_RST_FLAG)

typedef struct dp_icmp_err_ip_info {
	struct rte_ipv4_hdr *err_ipv4_hdr;
	rte_be16_t	l4_src_port;
	rte_be16_t	l4_dst_port;
} dp_icmp_err_ip_info;

uint16_t extract_inner_ethernet_header(struct rte_mbuf *pkt);
uint16_t extract_outer_ethernet_header(struct rte_mbuf *pkt);
int extract_inner_l3_header(struct rte_mbuf *pkt, void *hdr, uint16_t offset); // offset, ipv4/ipv6 header
int extract_inner_l4_header(struct rte_mbuf *pkt, void *hdr, uint16_t offset); // offset, tcp/udp/icmp header
int extract_outer_ipv6_header(struct rte_mbuf *pkt, void *hdr, uint16_t offset);
struct rte_ipv4_hdr *dp_get_ipv4_hdr(struct rte_mbuf *m);
struct rte_tcp_hdr *dp_get_tcp_hdr(struct rte_mbuf *m, uint16_t offset);
struct rte_udp_hdr *dp_get_udp_hdr(struct rte_mbuf *m, uint16_t offset);
struct rte_icmp_hdr *dp_get_icmp_hdr(struct rte_mbuf *m, uint16_t offset);
void dp_get_icmp_err_ip_hdr(struct rte_mbuf *m, struct dp_icmp_err_ip_info *err_ip_info);

void dp_change_icmp_err_l4_src_port(struct rte_mbuf *m, struct dp_icmp_err_ip_info *err_ip_info, uint16_t new_val);
void dp_change_l4_hdr_port(struct rte_mbuf *m, uint8_t port_type, uint16_t new_val);
void dp_change_icmp_identifier(struct rte_mbuf *m, uint16_t new_val);

// functions to craft actions/patterns are added later

void dp_set_eth_flow_item(struct rte_flow_item *item,
						  struct rte_flow_item_eth *eth_spec,
						  rte_be16_t type);

void dp_set_eth_dst_flow_item(struct rte_flow_item *item,
							  struct rte_flow_item_eth *eth_spec,
							  const struct rte_ether_addr *dst,
							  rte_be16_t type);

void dp_set_eth_src_dst_flow_item(struct rte_flow_item *item,
								  struct rte_flow_item_eth *eth_spec,
								  const struct rte_ether_addr *src,
								  const struct rte_ether_addr *dst,
								  rte_be16_t type);

void dp_set_ipv6_flow_item(struct rte_flow_item *item,
						   struct rte_flow_item_ipv6 *ipv6_spec,
						   uint8_t proto);

void dp_set_ipv6_src_flow_item(struct rte_flow_item *item,
							   struct rte_flow_item_ipv6 *ipv6_spec,
							   const uint8_t *src,
							   uint8_t proto);

void dp_set_ipv6_dst_flow_item(struct rte_flow_item *item,
							   struct rte_flow_item_ipv6 *ipv6_spec,
							   const uint8_t *dst,
							   uint8_t proto);

void dp_set_ipv4_dst_flow_item(struct rte_flow_item *item,
							   struct rte_flow_item_ipv4 *ipv4_spec,
							   rte_be32_t dst,
							   uint8_t proto);

void dp_set_ipv4_src_dst_flow_item(struct rte_flow_item *item,
								   struct rte_flow_item_ipv4 *ipv4_spec,
								   rte_be32_t src,
								   rte_be32_t dst,
								   uint8_t proto);

void dp_set_udp_src_flow_item(struct rte_flow_item *item,
							  struct rte_flow_item_udp *udp_spec,
							  rte_be16_t src_port);

void dp_set_udp_src_dst_flow_item(struct rte_flow_item *item,
								  struct rte_flow_item_udp *udp_spec,
								  rte_be16_t src_port,
								  rte_be16_t dst_port);

void dp_set_tcp_src_flow_item(struct rte_flow_item *item,
							  struct rte_flow_item_tcp *tcp_spec,
							  rte_be16_t src_port);

void dp_set_tcp_src_dst_flow_item(struct rte_flow_item *item,
								  struct rte_flow_item_tcp *tcp_spec,
								  rte_be16_t src_port,
								  rte_be16_t dst_port);

void dp_set_tcp_src_dst_noctrl_flow_item(struct rte_flow_item *item,
										 struct rte_flow_item_tcp *tcp_spec,
										 rte_be16_t src_port,
										 rte_be16_t dst_port);

void dp_set_icmp_flow_item(struct rte_flow_item *item,
						   struct rte_flow_item_icmp *icmp_spec,
						   uint8_t type);

void dp_set_icmp6_flow_item(struct rte_flow_item *item,
						    struct rte_flow_item_icmp6 *icmp6_spec,
						    uint8_t type);

void dp_set_mark_flow_item(struct rte_flow_item *item,
						   struct rte_flow_item_mark *mark_spec,
						   uint32_t marked_id);

void dp_set_tag_flow_item(struct rte_flow_item *item,
						  struct rte_flow_item_tag *tag_spec,
						  uint32_t tag_value,
						  uint8_t tag_index);

void dp_set_meta_flow_item(struct rte_flow_item *item,
						   struct rte_flow_item_meta *meta_spec,
						   uint32_t meta_value);

void dp_set_end_flow_item(struct rte_flow_item *item);


void dp_set_raw_decap_action(struct rte_flow_action *action,
							 struct rte_flow_action_raw_decap *raw_decap_action,
							 uint8_t *data_to_decap, size_t data_len);

void dp_set_raw_encap_action(struct rte_flow_action *action,
							 struct rte_flow_action_raw_encap *raw_encap_action,
							 uint8_t *data_to_encap, size_t data_len);

void dp_set_dst_mac_set_action(struct rte_flow_action *action,
							   struct rte_flow_action_set_mac *dst_mac_set_action,
							   struct rte_ether_addr *dst_mac);

void dp_set_src_mac_set_action(struct rte_flow_action *action,
							   struct rte_flow_action_set_mac *src_mac_set_action,
							   struct rte_ether_addr *src_mac);

void dp_set_ipv4_set_src_action(struct rte_flow_action *action,
								struct rte_flow_action_set_ipv4 *ipv4_action,
								rte_be32_t ipv4);

void dp_set_ipv4_set_dst_action(struct rte_flow_action *action,
								struct rte_flow_action_set_ipv4 *ipv4_action,
								rte_be32_t ipv4);

void dp_set_ipv6_set_src_action(struct rte_flow_action *action,
								struct rte_flow_action_set_ipv6 *ipv6_action,
								uint8_t *ipv6);

void dp_set_ipv6_set_dst_action(struct rte_flow_action *action,
								struct rte_flow_action_set_ipv6 *ipv6_action,
								uint8_t *ipv6);

void dp_set_trans_proto_set_src_action(struct rte_flow_action *action,
									   struct rte_flow_action_set_tp *tp_action,
									   uint16_t port);

void dp_set_trans_proto_set_dst_action(struct rte_flow_action *action,
									   struct rte_flow_action_set_tp *tp_action,
									   uint16_t port);

void dp_set_send_to_port_action(struct rte_flow_action *action,
								struct rte_flow_action_port_id *send_to_port_action,
								uint32_t port_id);

void dp_set_flow_age_action(struct rte_flow_action *action,
							struct rte_flow_action_age *flow_age_action,
							uint32_t timeout, void *age_context);

void dp_set_redirect_queue_action(struct rte_flow_action *action,
								  struct rte_flow_action_queue *queue_action,
								  uint16_t queue_index);

void dp_set_packet_mark_action(struct rte_flow_action *action,
							   struct rte_flow_action_mark *mark_action,
							   uint32_t marked_value);

void dp_set_set_tag_action(struct rte_flow_action *action,
						   struct rte_flow_action_set_tag *set_tag_action,
						   uint32_t tag_value, uint8_t index);

void dp_set_set_meta_action(struct rte_flow_action *action,
							struct rte_flow_action_set_meta *meta_action,
							uint32_t meta_value);

void dp_set_end_action(struct rte_flow_action *action);


int dp_destroy_rte_action_handle(uint16_t port_id, struct rte_flow_action_handle *handle, struct rte_flow_error *error);

struct rte_flow *dp_install_rte_flow(uint16_t port_id,
									 const struct rte_flow_attr *attr,
									 const struct rte_flow_item pattern[],
									 const struct rte_flow_action actions[]);

int dp_create_age_indirect_action(uint16_t port_id,
								  const struct rte_flow_attr *attr,
								  const struct rte_flow_action *age_action,
								  struct flow_value *conntrack,
								  struct flow_age_ctx *agectx);

#ifdef __cplusplus
}
#endif

#endif /* __INCLUDE_DP_RTE_FLOW_H */
