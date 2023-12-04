// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#ifndef __INCLUDE_DP_RTE_FLOW_HELPERS_H__
#define __INCLUDE_DP_RTE_FLOW_HELPERS_H__

#include <rte_flow.h>
#include "dp_error.h"
#include "dp_mbuf_dyn.h"
#include "nodes/ipv6_nd_node.h"
#include "rte_flow/dp_rte_flow.h"

#ifdef __cplusplus
extern "C"
{
#endif

#define DP_PKT_OFFLOAD_MARK 1

#define DP_TCP_CONTROL_FLAGS \
	(RTE_TCP_FIN_FLAG|RTE_TCP_SYN_FLAG|RTE_TCP_RST_FLAG)

#define DP_AGE_TIMEOUT_24BIT_MASK 0x00FFFFFF

union dp_flow_item_l3 {
	struct rte_flow_item_ipv4 ipv4;
	struct rte_flow_item_ipv6 ipv6;
};

union dp_flow_item_l4 {
	struct rte_flow_item_tcp tcp;
	struct rte_flow_item_udp udp;
	struct rte_flow_item_icmp icmp;
	struct rte_flow_item_icmp6 icmp6;
};

static const struct rte_flow_item_eth dp_flow_item_eth_mask = {
	.hdr.ether_type = 0xffff,
};
static const struct rte_flow_item_eth dp_flow_item_eth_dst_mask = {
	.hdr.dst_addr.addr_bytes = "\xff\xff\xff\xff\xff\xff",
	.hdr.ether_type = 0xffff,
};
static const struct rte_flow_item_eth dp_flow_item_eth_src_dst_mask = {
	.hdr.src_addr.addr_bytes = "\xff\xff\xff\xff\xff\xff",
	.hdr.dst_addr.addr_bytes = "\xff\xff\xff\xff\xff\xff",
	.hdr.ether_type = 0xffff,
};

static const struct rte_flow_item_ipv6 dp_flow_item_ipv6_mask = {
	.hdr.proto = 0xff,
};
static const struct rte_flow_item_ipv6 dp_flow_item_ipv6_src_mask = {
	.hdr.src_addr = "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff",
	.hdr.proto = 0xff,
};
static const struct rte_flow_item_ipv6 dp_flow_item_ipv6_dst_mask = {
	.hdr.dst_addr = "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff",
	.hdr.proto = 0xff,
};

static const struct rte_flow_item_ipv4 dp_flow_item_ipv4_dst_mask = {
	.hdr.dst_addr = 0xffffffff,
	.hdr.next_proto_id = 0xff,
};
static const struct rte_flow_item_ipv4 dp_flow_item_ipv4_src_dst_mask = {
	.hdr.src_addr = 0xffffffff,
	.hdr.dst_addr = 0xffffffff,
	.hdr.next_proto_id = 0xff,
};

static const struct rte_flow_item_udp dp_flow_item_udp_src_mask = {
	.hdr.src_port = 0xffff,
};
static const struct rte_flow_item_udp dp_flow_item_udp_dst_mask = {
	.hdr.dst_port = 0xffff,
};
static const struct rte_flow_item_udp dp_flow_item_udp_src_dst_mask = {
	.hdr.src_port = 0xffff,
	.hdr.dst_port = 0xffff,
};

static const struct rte_flow_item_tcp dp_flow_item_tcp_src_mask = {
	.hdr.src_port = 0xffff,
};
static const struct rte_flow_item_tcp dp_flow_item_tcp_src_dst_mask = {
	.hdr.src_port = 0xffff,
	.hdr.dst_port = 0xffff,
};
static const struct rte_flow_item_tcp dp_flow_item_tcp_src_dst_noctrl_mask = {
	.hdr.src_port = 0xffff,
	.hdr.dst_port = 0xffff,
	.hdr.tcp_flags = DP_TCP_CONTROL_FLAGS,
};

static const struct rte_flow_item_icmp dp_flow_item_icmp_mask = {
	.hdr.icmp_type = 0xff,
};

static const struct rte_flow_item_icmp6 dp_flow_item_icmp6_mask = {
	.type = 0xff,
};

static __rte_always_inline
void dp_set_eth_match_all_item(struct rte_flow_item *item)
{
	item->type = RTE_FLOW_ITEM_TYPE_ETH;
	item->spec = NULL;
	item->mask = NULL;
	item->last = NULL;
}

static __rte_always_inline
void dp_set_eth_flow_item(struct rte_flow_item *item,
						  struct rte_flow_item_eth *eth_spec,
						  rte_be16_t type)
{
	eth_spec->hdr.ether_type = type;
	item->type = RTE_FLOW_ITEM_TYPE_ETH;
	item->spec = eth_spec;
	item->mask = &dp_flow_item_eth_mask;
	item->last = NULL;
}

static __rte_always_inline
void dp_set_eth_dst_flow_item(struct rte_flow_item *item,
							  struct rte_flow_item_eth *eth_spec,
							  const struct rte_ether_addr *dst,
							  rte_be16_t type)
{
	memcpy(&(eth_spec->hdr.dst_addr), dst, sizeof(struct rte_ether_addr));
	eth_spec->hdr.ether_type = type;
	item->type = RTE_FLOW_ITEM_TYPE_ETH;
	item->spec = eth_spec;
	item->mask = &dp_flow_item_eth_dst_mask;
	item->last = NULL;
}

static __rte_always_inline
void dp_set_eth_src_dst_flow_item(struct rte_flow_item *item,
								  struct rte_flow_item_eth *eth_spec,
								  const struct rte_ether_addr *src,
								  const struct rte_ether_addr *dst,
								  rte_be16_t type)
{
	memcpy(&(eth_spec->hdr.src_addr), src, sizeof(struct rte_ether_addr));
	memcpy(&(eth_spec->hdr.dst_addr), dst, sizeof(struct rte_ether_addr));
	eth_spec->hdr.ether_type = type;
	item->type = RTE_FLOW_ITEM_TYPE_ETH;
	item->spec = eth_spec;
	item->mask = &dp_flow_item_eth_src_dst_mask;
	item->last = NULL;
}

static __rte_always_inline
void dp_set_ipv6_flow_item(struct rte_flow_item *item,
						   struct rte_flow_item_ipv6 *ipv6_spec,
						   uint8_t proto)
{
	ipv6_spec->hdr.proto = proto;
	item->type = RTE_FLOW_ITEM_TYPE_IPV6;
	item->spec = ipv6_spec;
	item->mask = &dp_flow_item_ipv6_mask;
	item->last = NULL;
}

static __rte_always_inline
void dp_set_ipv6_src_flow_item(struct rte_flow_item *item,
							   struct rte_flow_item_ipv6 *ipv6_spec,
							   const uint8_t *src,
							   uint8_t proto)
{
	memcpy(ipv6_spec->hdr.src_addr, src, 16);
	ipv6_spec->hdr.proto = proto;
	item->type = RTE_FLOW_ITEM_TYPE_IPV6;
	item->spec = ipv6_spec;
	item->mask = &dp_flow_item_ipv6_src_mask;
	item->last = NULL;
}

static __rte_always_inline
void dp_set_ipv6_dst_flow_item(struct rte_flow_item *item,
							   struct rte_flow_item_ipv6 *ipv6_spec,
							   const uint8_t *dst,
							   uint8_t proto)
{
	memcpy(ipv6_spec->hdr.dst_addr, dst, 16);
	ipv6_spec->hdr.proto = proto;
	item->type = RTE_FLOW_ITEM_TYPE_IPV6;
	item->spec = ipv6_spec;
	item->mask = &dp_flow_item_ipv6_dst_mask;
	item->last = NULL;
}

static __rte_always_inline
void dp_set_ipv4_dst_flow_item(struct rte_flow_item *item,
							   struct rte_flow_item_ipv4 *ipv4_spec,
							   rte_be32_t dst,
							   uint8_t proto)
{
	ipv4_spec->hdr.dst_addr = dst;
	ipv4_spec->hdr.next_proto_id = proto;
	item->type = RTE_FLOW_ITEM_TYPE_IPV4;
	item->spec = ipv4_spec;
	item->mask = &dp_flow_item_ipv4_dst_mask;
	item->last = NULL;
}

static __rte_always_inline
void dp_set_ipv4_src_dst_flow_item(struct rte_flow_item *item,
								   struct rte_flow_item_ipv4 *ipv4_spec,
								   rte_be32_t src,
								   rte_be32_t dst,
								   uint8_t proto)
{
	ipv4_spec->hdr.src_addr = src;
	ipv4_spec->hdr.dst_addr = dst;
	ipv4_spec->hdr.next_proto_id = proto;
	item->type = RTE_FLOW_ITEM_TYPE_IPV4;
	item->spec = ipv4_spec;
	item->mask = &dp_flow_item_ipv4_src_dst_mask;
	item->last = NULL;
}

static __rte_always_inline
void dp_set_udp_src_flow_item(struct rte_flow_item *item,
							  struct rte_flow_item_udp *udp_spec,
							  rte_be16_t src_port)
{
	udp_spec->hdr.src_port = src_port;
	item->type = RTE_FLOW_ITEM_TYPE_UDP;
	item->spec = udp_spec;
	item->mask = &dp_flow_item_udp_src_mask;
	item->last = NULL;
}

static __rte_always_inline
void dp_set_udp_dst_flow_item(struct rte_flow_item *item,
							  struct rte_flow_item_udp *udp_spec,
							  rte_be16_t dst_port)
{
	udp_spec->hdr.dst_port = dst_port;
	item->type = RTE_FLOW_ITEM_TYPE_UDP;
	item->spec = udp_spec;
	item->mask = &dp_flow_item_udp_dst_mask;
	item->last = NULL;
}

static __rte_always_inline
void dp_set_udp_src_dst_flow_item(struct rte_flow_item *item,
								  struct rte_flow_item_udp *udp_spec,
								  rte_be16_t src_port,
								  rte_be16_t dst_port)
{
	udp_spec->hdr.src_port = src_port;
	udp_spec->hdr.dst_port = dst_port;
	item->type = RTE_FLOW_ITEM_TYPE_UDP;
	item->spec = udp_spec;
	item->mask = &dp_flow_item_udp_src_dst_mask;
	item->last = NULL;
}

static __rte_always_inline
void dp_set_tcp_src_flow_item(struct rte_flow_item *item,
							  struct rte_flow_item_tcp *tcp_spec,
							  rte_be16_t src_port)
{
	tcp_spec->hdr.src_port = src_port;
	item->type = RTE_FLOW_ITEM_TYPE_TCP;
	item->spec = tcp_spec;
	item->mask = &dp_flow_item_tcp_src_mask;
	item->last = NULL;
}

static __rte_always_inline
void dp_set_tcp_src_dst_flow_item(struct rte_flow_item *item,
								  struct rte_flow_item_tcp *tcp_spec,
								  rte_be16_t src_port,
								  rte_be16_t dst_port)
{
	tcp_spec->hdr.src_port = src_port;
	tcp_spec->hdr.dst_port = dst_port;
	item->type = RTE_FLOW_ITEM_TYPE_TCP;
	item->spec = tcp_spec;
	item->mask = &dp_flow_item_tcp_src_dst_mask;
	item->last = NULL;
}

static __rte_always_inline
void dp_set_tcp_src_dst_noctrl_flow_item(struct rte_flow_item *item,
										 struct rte_flow_item_tcp *tcp_spec,
										 rte_be16_t src_port,
										 rte_be16_t dst_port)
{
	tcp_spec->hdr.src_port = src_port;
	tcp_spec->hdr.dst_port = dst_port;
	tcp_spec->hdr.tcp_flags = ~DP_TCP_CONTROL_FLAGS;
	item->type = RTE_FLOW_ITEM_TYPE_TCP;
	item->spec = tcp_spec;
	item->mask = &dp_flow_item_tcp_src_dst_noctrl_mask;
	item->last = NULL;
}

static __rte_always_inline
void dp_set_icmp_flow_item(struct rte_flow_item *item,
						   struct rte_flow_item_icmp *icmp_spec,
						   uint8_t type)
{
	icmp_spec->hdr.icmp_type = type;
	item->type = RTE_FLOW_ITEM_TYPE_ICMP;
	item->spec = icmp_spec;
	item->mask = &dp_flow_item_icmp_mask;
	item->last = NULL;
}

static __rte_always_inline
void dp_set_icmp6_flow_item(struct rte_flow_item *item,
						    struct rte_flow_item_icmp6 *icmp6_spec,
						    uint8_t type)
{
	icmp6_spec->type = type;
	item->type = RTE_FLOW_ITEM_TYPE_ICMP6;
	item->spec = icmp6_spec;
	item->mask = &dp_flow_item_icmp6_mask;
	item->last = NULL;
}

static __rte_always_inline
void dp_set_mark_flow_item(struct rte_flow_item *item,
						   struct rte_flow_item_mark *mark_spec,
						   uint32_t marked_id)
{
	mark_spec->id = marked_id;
	item->type = RTE_FLOW_ITEM_TYPE_MARK;
	item->spec = mark_spec;
	item->mask = &rte_flow_item_mark_mask;
	item->last = NULL;
}

static __rte_always_inline
void dp_set_tag_flow_item(struct rte_flow_item *item,
						  struct rte_flow_item_tag *tag_spec,
						  uint32_t tag_value,
						  uint8_t tag_index)
{
	tag_spec->data = tag_value;
	tag_spec->index = tag_index;
	item->type = RTE_FLOW_ITEM_TYPE_TAG;
	item->spec = tag_spec;
	item->mask = &rte_flow_item_tag_mask;
	item->last = NULL;
}

static __rte_always_inline
void dp_set_meta_flow_item(struct rte_flow_item *item,
						   struct rte_flow_item_meta *meta_spec,
						   uint32_t meta_value)
{
	meta_spec->data = meta_value;
	item->type = RTE_FLOW_ITEM_TYPE_META;
	item->spec = meta_spec;
	item->mask = &rte_flow_item_meta_mask;
	item->last = NULL;
}

static __rte_always_inline
void dp_set_end_flow_item(struct rte_flow_item *item)
{
	item->type = RTE_FLOW_ITEM_TYPE_END;
	item->spec = NULL;
	item->mask = NULL;
	item->last = NULL;
}

static __rte_always_inline
int dp_set_l4_flow_item(struct rte_flow_item *item,
						union dp_flow_item_l4 *l4_spec,
						const struct dp_flow *df)
{
	if (df->l4_type == DP_IP_PROTO_TCP)
		dp_set_tcp_src_dst_noctrl_flow_item(item, &l4_spec->tcp,
											df->l4_info.trans_port.src_port, df->l4_info.trans_port.dst_port);
	else if (df->l4_type == DP_IP_PROTO_UDP)
		dp_set_udp_src_dst_flow_item(item, &l4_spec->udp,
									 df->l4_info.trans_port.src_port, df->l4_info.trans_port.dst_port);
	else if (df->l4_type == DP_IP_PROTO_ICMP)
		dp_set_icmp_flow_item(item, &l4_spec->icmp, df->l4_info.icmp_field.icmp_type);
	else if (df->l4_type == DP_IP_PROTO_ICMPV6)
		dp_set_icmp6_flow_item(item, &l4_spec->icmp6, df->l4_info.icmp_field.icmp_type);
	else {
		DPS_LOG_ERR("Invalid L4 protocol", DP_LOG_PROTO(df->l4_type));
		return DP_ERROR;
	}
	return DP_OK;
}


static __rte_always_inline
void dp_set_raw_decap_action(struct rte_flow_action *action,
							 struct rte_flow_action_raw_decap *raw_decap_action,
							 uint8_t *data_to_decap, size_t data_len)
{
	raw_decap_action->data = data_to_decap;
	raw_decap_action->size = data_len;
	action->type = RTE_FLOW_ACTION_TYPE_RAW_DECAP;
	action->conf = raw_decap_action;
}

static __rte_always_inline
void dp_set_raw_encap_action(struct rte_flow_action *action,
							 struct rte_flow_action_raw_encap *raw_encap_action,
							 uint8_t *data_to_encap, size_t data_len)
{
	raw_encap_action->data = data_to_encap;
	raw_encap_action->size = data_len;
	action->type = RTE_FLOW_ACTION_TYPE_RAW_ENCAP;
	action->conf = raw_encap_action;
}

static __rte_always_inline
void dp_set_dst_mac_set_action(struct rte_flow_action *action,
							   struct rte_flow_action_set_mac *dst_mac_set_action,
							   const struct rte_ether_addr *dst_mac)
{
	rte_ether_addr_copy(dst_mac, (struct rte_ether_addr *)(dst_mac_set_action->mac_addr));
	action->type = RTE_FLOW_ACTION_TYPE_SET_MAC_DST;
	action->conf = dst_mac_set_action;
}

static __rte_always_inline
void dp_set_src_mac_set_action(struct rte_flow_action *action,
							   struct rte_flow_action_set_mac *src_mac_set_action,
							   const struct rte_ether_addr *src_mac)
{
	rte_ether_addr_copy(src_mac, (struct rte_ether_addr *)src_mac_set_action->mac_addr);
	action->type = RTE_FLOW_ACTION_TYPE_SET_MAC_SRC;
	action->conf = src_mac_set_action;
}

static __rte_always_inline
void dp_set_ipv4_set_src_action(struct rte_flow_action *action,
								struct rte_flow_action_set_ipv4 *ipv4_action,
								rte_be32_t ipv4)
{
	ipv4_action->ipv4_addr = ipv4;
	action->type = RTE_FLOW_ACTION_TYPE_SET_IPV4_SRC;
	action->conf = ipv4_action;
}

static __rte_always_inline
void dp_set_ipv4_set_dst_action(struct rte_flow_action *action,
								struct rte_flow_action_set_ipv4 *ipv4_action,
								rte_be32_t ipv4)
{
	ipv4_action->ipv4_addr = ipv4;
	action->type = RTE_FLOW_ACTION_TYPE_SET_IPV4_DST;
	action->conf = ipv4_action;
}

static __rte_always_inline
void dp_set_ipv6_set_src_action(struct rte_flow_action *action,
								struct rte_flow_action_set_ipv6 *ipv6_action,
								const uint8_t *ipv6)
{
	memcpy(ipv6_action->ipv6_addr, ipv6, sizeof(ipv6_action->ipv6_addr));
	action->type = RTE_FLOW_ACTION_TYPE_SET_IPV6_SRC;
	action->conf = ipv6_action;
}

static __rte_always_inline
void dp_set_ipv6_set_dst_action(struct rte_flow_action *action,
								struct rte_flow_action_set_ipv6 *ipv6_action,
								const uint8_t *ipv6)
{
	memcpy(ipv6_action->ipv6_addr, ipv6, sizeof(ipv6_action->ipv6_addr));
	action->type = RTE_FLOW_ACTION_TYPE_SET_IPV6_DST;
	action->conf = ipv6_action;
}

static __rte_always_inline
void dp_set_trans_proto_set_src_action(struct rte_flow_action *action,
									   struct rte_flow_action_set_tp *tp_action,
									   rte_be16_t port)
{
	tp_action->port = port;
	action->type = RTE_FLOW_ACTION_TYPE_SET_TP_SRC;
	action->conf = tp_action;
}

static __rte_always_inline
void dp_set_trans_proto_set_dst_action(struct rte_flow_action *action,
									   struct rte_flow_action_set_tp *tp_action,
									   rte_be16_t port)
{
	tp_action->port = port;
	action->type = RTE_FLOW_ACTION_TYPE_SET_TP_DST;
	action->conf = tp_action;
}

static __rte_always_inline
void dp_set_send_to_port_action(struct rte_flow_action *action,
								struct rte_flow_action_port_id *send_to_port_action,
								uint32_t port_id)
{
	send_to_port_action->original = 0; // original???
	send_to_port_action->reserved = 0;
	send_to_port_action->id = port_id;
	action->type = RTE_FLOW_ACTION_TYPE_PORT_ID;
	action->conf = send_to_port_action;
}

static __rte_always_inline
void dp_set_flow_age_action(struct rte_flow_action *action,
							struct rte_flow_action_age *flow_age_action,
							uint32_t timeout, void *age_context)
{
	// timeout has only 24 bits
	// should always fit, the value is just a #define'd constant (unless in testing mode)
	flow_age_action->timeout = timeout & DP_AGE_TIMEOUT_24BIT_MASK;
	flow_age_action->reserved = 0;
	flow_age_action->context = age_context;
	action->type = RTE_FLOW_ACTION_TYPE_AGE;
	action->conf = flow_age_action;
}

static __rte_always_inline
void dp_set_redirect_queue_action(struct rte_flow_action *action,
								  struct rte_flow_action_queue *queue_action,
								  uint16_t queue_index)
{
	queue_action->index = queue_index;
	action->type = RTE_FLOW_ACTION_TYPE_QUEUE;
	action->conf = queue_action;
}

static __rte_always_inline
void dp_set_packet_mark_action(struct rte_flow_action *action,
							   struct rte_flow_action_mark *mark_action,
							   uint32_t marked_value)
{
	mark_action->id = marked_value;
	action->type = RTE_FLOW_ACTION_TYPE_MARK;
	action->conf = mark_action;
}

static __rte_always_inline
void dp_set_set_tag_action(struct rte_flow_action *action,
						   struct rte_flow_action_set_tag *set_tag_action,
						   uint32_t tag_value)
{
	set_tag_action->data = tag_value;
	set_tag_action->mask = 0xffffffff;
	set_tag_action->index = 0;  // This function currently only supports one tag per packet
	action->type = RTE_FLOW_ACTION_TYPE_SET_TAG;
	action->conf = set_tag_action;
}

static __rte_always_inline
void dp_set_set_meta_action(struct rte_flow_action *action,
							struct rte_flow_action_set_meta *meta_action,
							uint32_t meta_value)
{
	meta_action->data = meta_value;
	meta_action->mask = 0xffffffff;
	action->type = RTE_FLOW_ACTION_TYPE_SET_META;
	action->conf = meta_action;
}

static __rte_always_inline
void dp_set_sample_action(struct rte_flow_action *action,
						  struct rte_flow_action_sample *sample_action,
						  uint32_t sample_ratio, struct rte_flow_action *sub_action)
{
	sample_action->ratio = sample_ratio;
	sample_action->actions = sub_action; // it seems that driver does not support null sub action
	action->type = RTE_FLOW_ACTION_TYPE_SAMPLE;
	action->conf = sample_action;
}

static __rte_always_inline
void dp_set_jump_group_action(struct rte_flow_action *action,
							  struct rte_flow_action_jump *jump_action,
							  uint32_t group_id)
{
	jump_action->group = group_id;
	action->type = RTE_FLOW_ACTION_TYPE_JUMP;
	action->conf = jump_action;
}

static __rte_always_inline
void dp_set_end_action(struct rte_flow_action *action)
{
	action->type = RTE_FLOW_ACTION_TYPE_END;
	action->conf = NULL;
}

#ifdef __cplusplus
}
#endif

#endif
