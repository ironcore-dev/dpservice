#include "rte_flow/dp_rte_flow.h"
#include "dp_error.h"
#include "dp_flow.h"
#include "dp_lpm.h"
#include "dp_nat.h"
#include "nodes/dhcp_node.h"
#include "dp_mbuf_dyn.h"
#include "nodes/ipv6_nd_node.h"

static const uint8_t ether_addr_mask[RTE_ETHER_ADDR_LEN] = "\xff\xff\xff\xff\xff\xff";
static const uint8_t ipv6_addr_mask[16] = "\xff\xff\xff\xff\xff\xff\xff\xff"
										  "\xff\xff\xff\xff\xff\xff\xff\xff";
static const uint8_t ipv4_addr_mask[4] = "\xff\xff\xff\xff";

uint16_t extract_inner_ethernet_header(struct rte_mbuf *pkt)
{
	struct rte_ether_hdr *eth_hdr;
	struct dp_flow *df;

	df = dp_get_flow_ptr(pkt);

	eth_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
	df->l3_type = ntohs(eth_hdr->ether_type);

	// mac address can be also extracted here, but I don't need them now
	return df->l3_type;
}

uint16_t extract_outer_ethernet_header(struct rte_mbuf *pkt)
{
	struct rte_ether_hdr *eth_hdr;
	struct dp_flow *df;

	df = dp_get_flow_ptr(pkt);

	eth_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
	df->tun_info.l3_type = ntohs(eth_hdr->ether_type);

	// mac address can be also extracted here, but I don't need them now

	return df->tun_info.l3_type;
}

int extract_inner_l3_header(struct rte_mbuf *pkt, void *hdr, uint16_t offset)
{
	struct dp_flow *df;
	struct rte_ipv4_hdr *ipv4_hdr;
	struct rte_ipv6_hdr *ipv6_hdr;

	df = dp_get_flow_ptr(pkt);
	if (df->l3_type == RTE_ETHER_TYPE_IPV4) {
		if (hdr)
			ipv4_hdr = (struct rte_ipv4_hdr *)hdr;
		else
			ipv4_hdr = rte_pktmbuf_mtod_offset(pkt, struct rte_ipv4_hdr *, offset);

		df->src.src_addr = ipv4_hdr->src_addr;
		df->dst.dst_addr = ipv4_hdr->dst_addr;
		df->l4_type = ipv4_hdr->next_proto_id;
		return df->l4_type;
	} else if (df->l3_type == RTE_ETHER_TYPE_IPV6) {
		if (hdr)
			ipv6_hdr = (struct rte_ipv6_hdr *)hdr;
		else
			ipv6_hdr = rte_pktmbuf_mtod_offset(pkt, struct rte_ipv6_hdr *, offset);

		rte_memcpy(df->dst.dst_addr6, ipv6_hdr->dst_addr, sizeof(df->dst.dst_addr6));
		rte_memcpy(df->src.src_addr6, ipv6_hdr->src_addr, sizeof(df->src.src_addr6));
		df->l4_type = ipv6_hdr->proto;
		return df->l4_type;
	}

	return DP_ERROR;
}

int extract_inner_l4_header(struct rte_mbuf *pkt, void *hdr, uint16_t offset)
{
	struct dp_flow *df;
	struct rte_tcp_hdr *tcp_hdr;
	struct rte_udp_hdr *udp_hdr;

	struct rte_icmp_hdr *icmp_hdr;
	struct icmp6hdr *icmp6_hdr;

	df = dp_get_flow_ptr(pkt);
	if (df->l4_type == DP_IP_PROTO_TCP) {
		if (hdr != NULL)
			tcp_hdr = (struct rte_tcp_hdr *)hdr;
		else
			tcp_hdr = rte_pktmbuf_mtod_offset(pkt, struct rte_tcp_hdr *, offset);

		df->l4_info.trans_port.dst_port = tcp_hdr->dst_port;
		df->l4_info.trans_port.src_port = tcp_hdr->src_port;
		return DP_OK;
	} else if (df->l4_type == DP_IP_PROTO_UDP) {
		if (hdr != NULL)
			udp_hdr = (struct rte_udp_hdr *)hdr;
		else
			udp_hdr = rte_pktmbuf_mtod_offset(pkt, struct rte_udp_hdr *, offset);

		df->l4_info.trans_port.dst_port = udp_hdr->dst_port;
		df->l4_info.trans_port.src_port = udp_hdr->src_port;
		return DP_OK;
	} else if (df->l4_type == DP_IP_PROTO_ICMP) {
		if (hdr != NULL)
			icmp_hdr = (struct rte_icmp_hdr *)hdr;
		else
			icmp_hdr = rte_pktmbuf_mtod_offset(pkt, struct rte_icmp_hdr *, offset);

		df->l4_info.icmp_field.icmp_type = icmp_hdr->icmp_type;
		df->l4_info.icmp_field.icmp_code = icmp_hdr->icmp_code;
		df->l4_info.icmp_field.icmp_identifier = icmp_hdr->icmp_ident;
		return DP_OK;
	} else if (df->l4_type == DP_IP_PROTO_ICMPV6) {
		if (hdr != NULL)
			icmp6_hdr = (struct icmp6hdr *)hdr;
		else
			icmp6_hdr = rte_pktmbuf_mtod_offset(pkt, struct icmp6hdr *, offset);

		df->l4_info.icmp_field.icmp_type = icmp6_hdr->icmp6_type;
		return DP_OK;
	}

	return DP_ERROR;
}

int extract_outer_ipv6_header(struct rte_mbuf *pkt, void *hdr, uint16_t offset)
{
	struct dp_flow *df = dp_get_flow_ptr(pkt);
	struct rte_ipv6_hdr *ipv6_hdr = NULL;

	if (hdr != NULL)
		ipv6_hdr = (struct rte_ipv6_hdr *)hdr;
	else
		ipv6_hdr = rte_pktmbuf_mtod_offset(pkt, struct rte_ipv6_hdr *, offset);

	if (!ipv6_hdr)
		return DP_ERROR;

	rte_memcpy(df->tun_info.ul_src_addr6, ipv6_hdr->src_addr, sizeof(df->tun_info.ul_src_addr6));
	rte_memcpy(df->tun_info.ul_dst_addr6, ipv6_hdr->dst_addr, sizeof(df->tun_info.ul_dst_addr6));
	df->tun_info.proto_id = ipv6_hdr->proto;
	return ipv6_hdr->proto;
}

struct rte_ipv4_hdr *dp_get_ipv4_hdr(struct rte_mbuf *m)
{
	struct rte_ipv4_hdr *ipv4_hdr;
	struct dp_flow *df;

	df = dp_get_flow_ptr(m);

	if (df->flags.flow_type == DP_FLOW_TYPE_INCOMING)
		ipv4_hdr = rte_pktmbuf_mtod(m, struct rte_ipv4_hdr *);
	else
		ipv4_hdr = rte_pktmbuf_mtod_offset(m, struct rte_ipv4_hdr *,
										   sizeof(struct rte_ether_hdr));

	return ipv4_hdr;
}

struct rte_tcp_hdr *dp_get_tcp_hdr(struct rte_mbuf *m, uint16_t offset)
{
	struct dp_flow *df;
	struct rte_tcp_hdr *tcp_hdr;

	df = dp_get_flow_ptr(m);
	if (df->l4_type == DP_IP_PROTO_TCP)
		tcp_hdr = rte_pktmbuf_mtod_offset(m, struct rte_tcp_hdr *, offset);
	else
		return NULL;

	return tcp_hdr;
}

struct rte_udp_hdr *dp_get_udp_hdr(struct rte_mbuf *m, uint16_t offset)
{
	struct dp_flow *df;
	struct rte_udp_hdr *udp_hdr;

	df = dp_get_flow_ptr(m);
	if (df->l4_type == DP_IP_PROTO_UDP)
		udp_hdr = rte_pktmbuf_mtod_offset(m, struct rte_udp_hdr *, offset);
	else
		return NULL;

	return udp_hdr;
}

struct rte_icmp_hdr *dp_get_icmp_hdr(struct rte_mbuf *m, uint16_t offset)
{
	struct dp_flow *df;
	struct rte_icmp_hdr *icmp_hdr;

	df = dp_get_flow_ptr(m);
	if (df->l4_type == DP_IP_PROTO_ICMP)
		icmp_hdr = rte_pktmbuf_mtod_offset(m, struct rte_icmp_hdr *, offset);
	else
		return NULL;

	return icmp_hdr;
}

void dp_get_icmp_err_ip_hdr(struct rte_mbuf *m, struct dp_icmp_err_ip_info *err_ip_info)
{
	struct dp_flow *df;
	struct rte_ipv4_hdr *ipv4_hdr;
	struct rte_icmp_hdr *icmp_hdr;

	ipv4_hdr = dp_get_ipv4_hdr(m);

	df = dp_get_flow_ptr(m);

	if (df->l4_type == DP_IP_PROTO_ICMP) {
		icmp_hdr = (struct rte_icmp_hdr *)(ipv4_hdr+1);

		if (icmp_hdr->icmp_type == DP_IP_ICMP_TYPE_ERROR) {
			err_ip_info->err_ipv4_hdr = (struct rte_ipv4_hdr *)(icmp_hdr+1);
			if (err_ip_info->err_ipv4_hdr->next_proto_id == DP_IP_PROTO_TCP
				|| err_ip_info->err_ipv4_hdr->next_proto_id == DP_IP_PROTO_UDP) {

				rte_memcpy(&(err_ip_info->l4_src_port), (char *)err_ip_info->err_ipv4_hdr + err_ip_info->err_ipv4_hdr->ihl * 4, 2);
				rte_memcpy(&(err_ip_info->l4_dst_port), (char *)err_ip_info->err_ipv4_hdr + err_ip_info->err_ipv4_hdr->ihl * 4 + 2, 2);
			}
		}
	}
}

void dp_change_icmp_err_l4_src_port(struct rte_mbuf *m, struct dp_icmp_err_ip_info *err_ip_info, uint16_t new_val)
{
	struct rte_ipv4_hdr *ipv4_hdr;
	struct rte_icmp_hdr *icmp_hdr;
	rte_be16_t new_src_port = htons(new_val);

	ipv4_hdr = dp_get_ipv4_hdr(m);

	icmp_hdr = (struct rte_icmp_hdr *)(ipv4_hdr + 1);

	if (icmp_hdr->icmp_type == DP_IP_ICMP_TYPE_ERROR) {
		err_ip_info->err_ipv4_hdr = (struct rte_ipv4_hdr *)(icmp_hdr + 1);
		if (err_ip_info->err_ipv4_hdr->next_proto_id == DP_IP_PROTO_TCP
			|| err_ip_info->err_ipv4_hdr->next_proto_id == DP_IP_PROTO_UDP) {

			rte_memcpy((char *)err_ip_info->err_ipv4_hdr + err_ip_info->err_ipv4_hdr->ihl * 4, &new_src_port, sizeof(new_src_port));
		}
	}
}

void dp_change_l4_hdr_port(struct rte_mbuf *m, uint8_t port_type, uint16_t new_val)
{
	struct dp_flow *df = dp_get_flow_ptr(m);
	struct rte_ipv4_hdr *ipv4_hdr;
	struct rte_tcp_hdr *tcp_hdr;
	struct rte_udp_hdr *udp_hdr;
	rte_be16_t new_port = htons(new_val);

	ipv4_hdr = dp_get_ipv4_hdr(m);
	if (df->l4_type == DP_IP_PROTO_TCP) {
		tcp_hdr = (struct rte_tcp_hdr *)(ipv4_hdr + 1);
		if (port_type == DP_L4_PORT_DIR_SRC)
			tcp_hdr->src_port = new_port;
		else
			tcp_hdr->dst_port = new_port;
	} else {
		udp_hdr = (struct rte_udp_hdr *)(ipv4_hdr + 1);
		if (port_type == DP_L4_PORT_DIR_SRC)
			udp_hdr->src_port = new_port;
		else
			udp_hdr->dst_port = new_port;
	}
}

void dp_change_icmp_identifier(struct rte_mbuf *m, uint16_t new_val)
{
	struct rte_icmp_hdr *icmp_hdr;
	rte_be16_t old_identifier;
	uint32_t cksum;

	icmp_hdr = (struct rte_icmp_hdr *)(dp_get_ipv4_hdr(m) + 1);
	old_identifier = icmp_hdr->icmp_ident;
	icmp_hdr->icmp_ident = htons(new_val);

	// the approach of adding up vectors from icmp_hdr one by one is not durable since data field is not
	// provided in struct rte_icmp_hdr
	cksum = (~(icmp_hdr->icmp_cksum)) & 0xffff;
	cksum += (~old_identifier) & 0xffff;
	cksum += icmp_hdr->icmp_ident & 0xffff;
	cksum = (cksum & 0xffff) + (cksum >> 16);
	cksum = (cksum & 0xffff) + (cksum >> 16);

	icmp_hdr->icmp_cksum = (~cksum) & 0xffff;
}


void create_rte_flow_rule_attr(struct rte_flow_attr *attr, uint32_t group, uint32_t priority, uint32_t ingress, uint32_t egress, uint32_t transfer)
{

	memset(attr, 0, sizeof(struct rte_flow_attr));

	attr->group = group;
	attr->ingress = ingress;
	attr->egress = egress;
	attr->priority = priority;
	attr->transfer = transfer;
}

int insert_ethernet_match_pattern(struct rte_flow_item *pattern, int pattern_cnt,
								  struct rte_flow_item_eth *eth_spec,
								  struct rte_flow_item_eth *eth_mask,
								  struct rte_ether_addr *src, size_t nr_src_mask_len,
								  struct rte_ether_addr *dst, size_t nr_dst_mask_len,
								  rte_be16_t type)
{

	memset(eth_spec, 0, sizeof(struct rte_flow_item_eth));
	memset(eth_mask, 0, sizeof(struct rte_flow_item_eth));

	if (src) {
		memcpy(&(eth_spec->src), src, nr_src_mask_len);
		memcpy(&(eth_mask->src), ether_addr_mask, nr_src_mask_len);
	}

	if (dst) {
		memcpy(&(eth_spec->dst), dst, nr_dst_mask_len);
		memcpy(&(eth_mask->dst), ether_addr_mask, nr_dst_mask_len);
	}

	eth_spec->type = type;
	eth_mask->type = htons(0xffff);

	pattern[pattern_cnt].type = RTE_FLOW_ITEM_TYPE_ETH;
	pattern[pattern_cnt].spec = eth_spec;
	pattern[pattern_cnt].mask = eth_mask;

	return ++pattern_cnt;
}

int insert_ipv6_match_pattern(struct rte_flow_item *pattern, int pattern_cnt,
							  struct rte_flow_item_ipv6 *ipv6_spec,
							  struct rte_flow_item_ipv6 *ipv6_mask,
							  uint8_t *src, size_t nr_src_mask_len,
							  uint8_t *dst, size_t nr_dst_mask_len,
							  uint8_t proto)
{
	memset(ipv6_spec, 0, sizeof(struct rte_flow_item_ipv6));
	memset(ipv6_mask, 0, sizeof(struct rte_flow_item_ipv6));

	if (src) {
		memcpy(ipv6_spec->hdr.src_addr, src, nr_src_mask_len);
		memcpy(ipv6_mask->hdr.src_addr, ipv6_addr_mask, nr_src_mask_len);
	}

	if (dst) {
		memcpy(ipv6_spec->hdr.dst_addr, dst, nr_dst_mask_len);
		memcpy(ipv6_mask->hdr.dst_addr, ipv6_addr_mask, nr_dst_mask_len);
	}

	ipv6_spec->hdr.proto = proto;
	ipv6_mask->hdr.proto = 0xff;

	pattern[pattern_cnt].type = RTE_FLOW_ITEM_TYPE_IPV6;
	pattern[pattern_cnt].spec = ipv6_spec;
	pattern[pattern_cnt].mask = ipv6_mask;

	return ++pattern_cnt;
}

// this is a pure function that only take primitive information
int insert_ipv4_match_pattern(struct rte_flow_item *pattern, int pattern_cnt,
								struct rte_flow_item_ipv4 *ipv4_spec,
								struct rte_flow_item_ipv4 *ipv4_mask,
								rte_be32_t *src, size_t nr_src_mask_len,
								rte_be32_t *dst, size_t nr_dst_mask_len,
								uint8_t proto)
{
	memset(ipv4_spec, 0, sizeof(struct rte_flow_item_ipv4));
	memset(ipv4_mask, 0, sizeof(struct rte_flow_item_ipv4));

	if (src) {
		ipv4_spec->hdr.src_addr = *src;
		memcpy(&ipv4_mask->hdr.src_addr, ipv4_addr_mask, nr_src_mask_len);
	}

	if (dst) {
		ipv4_spec->hdr.dst_addr = *dst;
		memcpy(&ipv4_mask->hdr.dst_addr, ipv4_addr_mask, nr_dst_mask_len);
	}

	ipv4_spec->hdr.next_proto_id = proto;
	ipv4_mask->hdr.next_proto_id = 0xff;

	pattern[pattern_cnt].type = RTE_FLOW_ITEM_TYPE_IPV4;
	pattern[pattern_cnt].spec = ipv4_spec;
	pattern[pattern_cnt].mask = ipv4_mask;

	return ++pattern_cnt;
}

int insert_udp_match_pattern(struct rte_flow_item *pattern, int pattern_cnt,
							 struct rte_flow_item_udp *udp_spec,
							 struct rte_flow_item_udp *udp_mask,
							 rte_be16_t src_port, rte_be16_t dst_port)
{
	memset(udp_spec, 0, sizeof(struct rte_flow_item_udp));
	memset(udp_mask, 0, sizeof(struct rte_flow_item_udp));

	// Who is going to match a port that is 0? Let's assume that port>0 is a valid one.
	if (src_port) {
		udp_spec->hdr.src_port = src_port;
		udp_mask->hdr.src_port = 0xffff;
	}

	if (dst_port) {
		udp_spec->hdr.dst_port = dst_port;
		udp_mask->hdr.dst_port = 0xffff;
	}

	pattern[pattern_cnt].type = RTE_FLOW_ITEM_TYPE_UDP;
	pattern[pattern_cnt].spec = udp_spec;
	pattern[pattern_cnt].mask = udp_mask;

	return ++pattern_cnt;
}

int insert_tcp_match_pattern(struct rte_flow_item *pattern, int pattern_cnt,
							 struct rte_flow_item_tcp *tcp_spec,
							 struct rte_flow_item_tcp *tcp_mask,
							 rte_be16_t src_port, rte_be16_t dst_port,
							 uint8_t tcp_flags)
{
	memset(tcp_spec, 0, sizeof(struct rte_flow_item_tcp));
	memset(tcp_mask, 0, sizeof(struct rte_flow_item_tcp));

	// Who is going to match a port that is 0? Let's assume that port>0 is a valid one.
	if (src_port) {
		tcp_spec->hdr.src_port = src_port;
		tcp_mask->hdr.src_port = 0xffff;
	}

	if (dst_port) {
		tcp_spec->hdr.dst_port = dst_port;
		tcp_mask->hdr.dst_port = 0xffff;
	}

	if (tcp_flags) {
		tcp_spec->hdr.tcp_flags = ~tcp_flags;
		tcp_mask->hdr.tcp_flags = tcp_flags;
	}

	pattern[pattern_cnt].type = RTE_FLOW_ITEM_TYPE_TCP;
	pattern[pattern_cnt].spec = tcp_spec;
	pattern[pattern_cnt].mask = tcp_mask;

	return ++pattern_cnt;
}

int insert_icmp_match_pattern(struct rte_flow_item *pattern, int pattern_cnt,
							  struct rte_flow_item_icmp *icmp_spec,
							  struct rte_flow_item_icmp *icmp_mask,
							  uint8_t type)
{
	memset(icmp_spec, 0, sizeof(struct rte_flow_item_icmp));
	memset(icmp_mask, 0, sizeof(struct rte_flow_item_icmp));

	icmp_spec->hdr.icmp_type = type;
	icmp_spec->hdr.icmp_type = 0xff;

	pattern[pattern_cnt].type = RTE_FLOW_ITEM_TYPE_ICMP;
	pattern[pattern_cnt].spec = icmp_spec;
	pattern[pattern_cnt].mask = icmp_mask;

	return ++pattern_cnt;
}

int insert_icmpv6_match_pattern(struct rte_flow_item *pattern, int pattern_cnt,
								struct rte_flow_item_icmp6 *icmp6_spec,
								struct rte_flow_item_icmp6 *icmp6_mask,
								uint8_t type)
{
	memset(icmp6_spec, 0, sizeof(struct rte_flow_item_icmp6));
	memset(icmp6_mask, 0, sizeof(struct rte_flow_item_icmp6));

	icmp6_spec->type = type;
	icmp6_mask->type = 0xff;

	pattern[pattern_cnt].type = RTE_FLOW_ITEM_TYPE_ICMP6;
	pattern[pattern_cnt].spec = icmp6_spec;
	pattern[pattern_cnt].mask = icmp6_mask;

	return ++pattern_cnt;
}

int insert_packet_mark_match_pattern(struct rte_flow_item *pattern, int pattern_cnt,
									struct rte_flow_item_mark *mark_spec,
									struct rte_flow_item_mark *mark_mask,
									uint32_t marked_id)
{
	memset(mark_spec, 0, sizeof(struct rte_flow_item_mark));
	memset(mark_mask, 0, sizeof(struct rte_flow_item_mark));

	mark_spec->id = marked_id;
	mark_mask->id = rte_flow_item_mark_mask.id;

	pattern[pattern_cnt].type = RTE_FLOW_ITEM_TYPE_MARK;
	pattern[pattern_cnt].spec = mark_spec;
	pattern[pattern_cnt].mask = mark_mask;

	return ++pattern_cnt;
}

int insert_tag_match_pattern(struct rte_flow_item *pattern, int pattern_cnt,
									struct rte_flow_item_tag *tag_spec,
									struct rte_flow_item_tag *tag_mask,
									uint32_t tag_value, uint8_t tag_index)
{
	memset(tag_spec, 0, sizeof(struct rte_flow_item_tag));
	memset(tag_mask, 0, sizeof(struct rte_flow_item_tag));

	tag_spec->data = tag_value;
	tag_spec->index = tag_index;

	tag_mask->data = rte_flow_item_tag_mask.data;
	tag_mask->index = rte_flow_item_tag_mask.index;

	pattern[pattern_cnt].type = RTE_FLOW_ITEM_TYPE_TAG;
	pattern[pattern_cnt].spec = tag_spec;
	pattern[pattern_cnt].mask = tag_mask;

	return ++pattern_cnt;
}

int insert_meta_match_pattern(struct rte_flow_item *pattern, int pattern_cnt,
							struct rte_flow_item_meta *meta_spec,
							struct rte_flow_item_meta *meta_mask,
							uint32_t meta_value)
{
	memset(meta_spec, 0, sizeof(struct rte_flow_item_meta));
	memset(meta_mask, 0, sizeof(struct rte_flow_item_meta));

	meta_spec->data = meta_value;

	meta_mask->data = 0xffffffff;

	pattern[pattern_cnt].type = RTE_FLOW_ITEM_TYPE_META;
	pattern[pattern_cnt].spec = meta_spec;
	pattern[pattern_cnt].mask = meta_mask;

	return ++pattern_cnt;
}

int insert_end_match_pattern(struct rte_flow_item *pattern, int pattern_cnt)
{
	pattern[pattern_cnt].type = RTE_FLOW_ITEM_TYPE_END;
	return ++pattern_cnt;
}


int create_raw_decap_action(struct rte_flow_action *action, int action_cnt,
							struct rte_flow_action_raw_decap *raw_decap_action,
							uint8_t *data_to_decap, size_t data_len)
{
	raw_decap_action->data = data_to_decap;
	raw_decap_action->size = data_len;

	action[action_cnt].type = RTE_FLOW_ACTION_TYPE_RAW_DECAP;
	action[action_cnt].conf = raw_decap_action;
	return ++action_cnt;
}

int create_raw_encap_action(struct rte_flow_action *action, int action_cnt,
							struct rte_flow_action_raw_encap *raw_encap_action,
							uint8_t *data_to_encap, size_t data_len)
{
	raw_encap_action->data = data_to_encap;
	raw_encap_action->size = data_len;

	action[action_cnt].type = RTE_FLOW_ACTION_TYPE_RAW_ENCAP;
	action[action_cnt].conf = raw_encap_action;

	return ++action_cnt;
}

int create_dst_mac_set_action(struct rte_flow_action *action, int action_cnt,
							  struct rte_flow_action_set_mac *dst_mac_set_action,
							  struct rte_ether_addr *dst_mac)
{
	rte_ether_addr_copy(dst_mac, (struct rte_ether_addr *)(dst_mac_set_action->mac_addr));
	action[action_cnt].type = RTE_FLOW_ACTION_TYPE_SET_MAC_DST;
	action[action_cnt].conf = dst_mac_set_action;

	return ++action_cnt;
}

int create_src_mac_set_action(struct rte_flow_action *action, int action_cnt,
							  struct rte_flow_action_set_mac *src_mac_set_action,
							  struct rte_ether_addr *src_mac)
{
	rte_ether_addr_copy(src_mac, (struct rte_ether_addr *)src_mac_set_action->mac_addr);
	action[action_cnt].type = RTE_FLOW_ACTION_TYPE_SET_MAC_SRC;
	action[action_cnt].conf = src_mac_set_action;

	return ++action_cnt;
}

int create_ipv4_set_action(struct rte_flow_action *action, int action_cnt,
						   struct rte_flow_action_set_ipv4 *ipv4_action,
						   rte_be32_t ipv4, bool dir)
{
	ipv4_action->ipv4_addr = ipv4;

	if (dir == DP_IS_DST)
		action[action_cnt].type = RTE_FLOW_ACTION_TYPE_SET_IPV4_DST;
	else
		action[action_cnt].type = RTE_FLOW_ACTION_TYPE_SET_IPV4_SRC;

	action[action_cnt].conf = ipv4_action;

	return ++action_cnt;
}

int create_ipv6_set_action(struct rte_flow_action *action, int action_cnt,
						   struct rte_flow_action_set_ipv6 *ipv6_action,
						   uint8_t *ipv6, bool dir)
{
	memcpy(ipv6_action->ipv6_addr, ipv6, sizeof(ipv6_action->ipv6_addr));

	if (dir == DP_IS_DST)
		action[action_cnt].type = RTE_FLOW_ACTION_TYPE_SET_IPV6_DST;
	else
		action[action_cnt].type = RTE_FLOW_ACTION_TYPE_SET_IPV6_SRC;

	action[action_cnt].conf = ipv6_action;

	return ++action_cnt;
}

int create_trans_proto_set_action(struct rte_flow_action *action, int action_cnt,
									struct rte_flow_action_set_tp *tp_action,
									uint16_t port, bool dir)
{
	tp_action->port = htons(port);

	if (dir == DP_IS_DST)
		action[action_cnt].type = RTE_FLOW_ACTION_TYPE_SET_TP_DST;
	else
		action[action_cnt].type = RTE_FLOW_ACTION_TYPE_SET_TP_SRC;

	action[action_cnt].conf = tp_action;

	return ++action_cnt;
}

int create_send_to_port_action(struct rte_flow_action *action, int action_cnt,
							   struct rte_flow_action_port_id *send_to_port_action,
							   uint32_t port_id)
{
	send_to_port_action->original = 0; // original???
	send_to_port_action->reserved = 0;
	send_to_port_action->id = port_id;

	action[action_cnt].type = RTE_FLOW_ACTION_TYPE_PORT_ID;
	action[action_cnt].conf = send_to_port_action;

	return ++action_cnt;
}

int create_flow_age_action(struct rte_flow_action *action, int action_cnt,
						   struct rte_flow_action_age *flow_age_action,
						   uint32_t timeout, void *age_context)
{
	flow_age_action->timeout = timeout;
	flow_age_action->reserved = 0;
	flow_age_action->context = age_context;

	action[action_cnt].type = RTE_FLOW_ACTION_TYPE_AGE;
	action[action_cnt].conf = flow_age_action;

	return ++action_cnt;
}

int create_redirect_queue_action(struct rte_flow_action *action, int action_cnt,
								 struct rte_flow_action_queue *queue_action,
								 uint16_t queue_index)
{
	queue_action->index = queue_index;

	action[action_cnt].type = RTE_FLOW_ACTION_TYPE_QUEUE;
	action[action_cnt].conf = queue_action;

	return ++action_cnt;
}

int create_packet_mark_action(struct rte_flow_action *action, int action_cnt,
							struct rte_flow_action_mark *mark_action,
							uint32_t marked_value)
{
	mark_action->id =  marked_value;

	action[action_cnt].type = RTE_FLOW_ACTION_TYPE_MARK;
	action[action_cnt].conf = mark_action;

	return ++action_cnt;
}

int create_set_tag_action(struct rte_flow_action *action, int action_cnt,
							struct rte_flow_action_set_tag *set_tag_action,
							uint32_t tag_value, __rte_unused uint8_t index)
{
	set_tag_action->data =  tag_value;
	set_tag_action->mask =  0xffffffff;
	set_tag_action->index = 0;  // This function currently only supports one tag per packet

	action[action_cnt].type = RTE_FLOW_ACTION_TYPE_SET_TAG;
	action[action_cnt].conf = set_tag_action;

	return ++action_cnt;
}

int create_set_meta_action(struct rte_flow_action *action, int action_cnt,
							struct rte_flow_action_set_meta *meta_action,
							uint32_t meta_value)
{
	meta_action->data =  meta_value;
	meta_action->mask = 0xffffffff;

	action[action_cnt].type = RTE_FLOW_ACTION_TYPE_SET_META;
	action[action_cnt].conf = meta_action;

	return ++action_cnt;
}

int create_end_action(struct rte_flow_action *action, int action_cnt)
{
	action[action_cnt].type = RTE_FLOW_ACTION_TYPE_END;
	return ++action_cnt;
}


// flow aging related config is highly customized, thus put them into a function in case different agectx needs
// to be configured
void free_allocated_agectx(struct flow_age_ctx *agectx)
{
	struct rte_flow_error error;

	if (agectx) {
		if (agectx->handle) {
			if (DP_FAILED(dp_destroy_rte_action_handle(agectx->port_id, agectx->handle, &error)))
				DPS_LOG_ERR("Failed to remove an indirect action", DP_LOG_PORTID(agectx->port_id));
		}
		rte_free(agectx);
	}
}

void config_allocated_agectx(struct flow_age_ctx *agectx, uint16_t port_id,
							struct dp_flow *df, struct rte_flow *flow)
{
	agectx->cntrack = df->conntrack;
	agectx->rte_flow = flow;
	agectx->port_id = port_id;
	dp_ref_inc(&agectx->cntrack->ref_count);
}


struct rte_flow *validate_and_install_rte_flow(uint16_t port_id,
												const struct rte_flow_attr *attr,
												const struct rte_flow_item pattern[],
												const struct rte_flow_action action[])
{
	int ret;
	struct rte_flow *flow;
	struct rte_flow_error error = {
		.message = "(no stated reason)",
	};

	ret = rte_flow_validate(port_id, attr, pattern, action, &error);
	if (ret) {
		DPS_LOG_ERR("Flow cannot be validated", DP_LOG_FLOW_ERROR(error.message), DP_LOG_PORTID(port_id), DP_LOG_RET(ret));
		return NULL;
	}

	flow = rte_flow_create(port_id, attr, pattern, action, &error);
	if (!flow) {
		DPS_LOG_ERR("Flow cannot be created", DP_LOG_PORTID(port_id), DP_LOG_FLOW_ERROR(error.message));
		return NULL;
	}
	DPS_LOG_DEBUG("Installed a flow rule", DP_LOG_PORTID(port_id));
	return flow;
}

int dp_create_age_indirect_action(const struct rte_flow_attr *attr, uint16_t port_id,
								  struct dp_flow *df, struct rte_flow_action *age_action, struct flow_age_ctx *agectx)
{
	if (df->l4_type != IPPROTO_TCP)
		return DP_OK;

	struct rte_flow_indir_action_conf age_indirect_conf = {
		.ingress = attr->ingress,
		.egress = attr->egress,
		.transfer = attr->transfer,
	};
	struct rte_flow_error error = {
		.message = "(no stated reason)",
	};
	struct rte_flow_action_handle *result;

	result = rte_flow_action_handle_create(port_id, &age_indirect_conf, age_action, &error);
	if (!result) {
		DPS_LOG_ERR("Flow's age cannot be configured as indirect", DP_LOG_FLOW_ERROR(error.message));
		return DP_ERROR;
	}

	if (DP_FAILED(dp_add_rte_age_ctx(df->conntrack, agectx))) {
		if (DP_FAILED(dp_destroy_rte_action_handle(port_id, result, &error)))
			DPS_LOG_ERR("Failed to remove an indirect action", DP_LOG_PORTID(port_id));
		DPS_LOG_ERR("Failed to store agectx in conntrack object");
		return DP_ERROR;
	}

	agectx->handle = result;
	return DP_OK;
}
