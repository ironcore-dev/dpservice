#include "dp_rte_flow.h"
#include "dp_flow.h"
#include "dp_lpm.h"
#include "nodes/dhcp_node.h"
#include "node_api.h"
#include "nodes/ipv6_nd_node.h"

const static uint8_t ether_addr_mask[RTE_ETHER_ADDR_LEN] = "\xff\xff\xff\xff\xff\xff";
const static uint8_t ipv6_addr_mask[16] = "\xff\xff\xff\xff\xff\xff\xff\xff"
										  "\xff\xff\xff\xff\xff\xff\xff\xff";

uint16_t extract_inner_ethernet_header(struct rte_mbuf *pkt)
{

	struct rte_ether_hdr *eth_hdr;
	struct dp_flow *df;

	df = get_dp_flow_ptr(pkt);

	eth_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
	df->l3_type = ntohs(eth_hdr->ether_type);

	// mac address can be also extracted here, but I don't need them now
	return df->l3_type;
}

uint16_t extract_outter_ethernet_header(struct rte_mbuf *pkt)
{

	struct rte_ether_hdr *eth_hdr;
	struct dp_flow *df;

	df = get_dp_flow_ptr(pkt);

	eth_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
	df->tun_info.l3_type = ntohs(eth_hdr->ether_type);

	// mac address can be also extracted here, but I don't need them now

	return df->l3_type;
}

int extract_inner_l3_header(struct rte_mbuf *pkt, void *hdr, uint16_t offset)
{
	struct dp_flow *df;
	struct rte_ipv4_hdr *ipv4_hdr;
	struct rte_ipv6_hdr *ipv6_hdr;

	df = get_dp_flow_ptr(pkt);
	if (df->l3_type == RTE_ETHER_TYPE_IPV4)
	{
		if (hdr)
			ipv4_hdr = (struct rte_ipv4_hdr *)hdr;
		else
			ipv4_hdr = rte_pktmbuf_mtod_offset(pkt, struct rte_ipv4_hdr *, offset);

		df->src.src_addr = ipv4_hdr->src_addr;
		df->dst.dst_addr = ipv4_hdr->dst_addr;
		df->l4_type = ipv4_hdr->next_proto_id;
		// printf("extract for ipv4 header, protoid is %#x \n",ipv4_hdr->next_proto_id);
		return df->l4_type;
	}
	else if (df->l3_type == RTE_ETHER_TYPE_IPV6)
	{
		if (hdr)
			ipv6_hdr = (struct rte_ipv6_hdr *)hdr;
		else
			ipv6_hdr = rte_pktmbuf_mtod_offset(pkt, struct rte_ipv6_hdr *, offset);

		rte_memcpy(df->dst.dst_addr6, ipv6_hdr->dst_addr, sizeof(df->dst.dst_addr6));
		rte_memcpy(df->src.src_addr6, ipv6_hdr->src_addr, sizeof(df->src.src_addr6));
		df->l4_type = ipv6_hdr->proto;
		return df->l4_type;
	}

	return -1;
}

int extract_inner_l4_header(struct rte_mbuf *pkt, void *hdr, uint16_t offset)
{

	struct dp_flow *df;
	struct rte_tcp_hdr *tcp_hdr;
	struct rte_udp_hdr *udp_hdr;

	struct rte_icmp_hdr *icmp_hdr;
	struct icmp6hdr *icmp6_hdr;

	df = get_dp_flow_ptr(pkt);
	if (df->l4_type == DP_IP_PROTO_TCP)
	{
		if (hdr != NULL)
		{
			tcp_hdr = (struct rte_tcp_hdr *)hdr;
		}
		else
		{
			tcp_hdr = rte_pktmbuf_mtod_offset(pkt, struct rte_tcp_hdr *, offset);
		}
		df->dst_port = tcp_hdr->dst_port;
		df->src_port = tcp_hdr->src_port;
		return 0;
	}
	else if (df->l4_type == DP_IP_PROTO_UDP)
	{
		if (hdr != NULL)
		{
			udp_hdr = (struct rte_udp_hdr *)hdr;
		}
		else
		{
			udp_hdr = rte_pktmbuf_mtod_offset(pkt, struct rte_udp_hdr *, offset);
		}
		df->dst_port = udp_hdr->dst_port;
		df->src_port = udp_hdr->src_port;
		return 0;
	}
	else if (df->l4_type == DP_IP_PROTO_ICMP)
	{
		if (hdr != NULL)
		{
			icmp_hdr = (struct rte_icmp_hdr *)hdr;
		}
		else
		{
			icmp_hdr = rte_pktmbuf_mtod_offset(pkt, struct rte_icmp_hdr *, offset);
		}
		df->icmp_type = icmp_hdr->icmp_type;
		return 0;
	}
	else if (df->l4_type == DP_IP_PROTO_ICMPV6)
	{
		if (hdr != NULL)
		{
			icmp6_hdr = (struct icmp6hdr *)hdr;
		}
		else
		{
			icmp6_hdr = rte_pktmbuf_mtod_offset(pkt, struct icmp6hdr *, offset);
		}
		df->icmp_type = icmp6_hdr->icmp6_type;
		return 0;
	}

	return -1;
}

// int extract_inner_l3_l4_header(struct rte_mbuf* pkt,uint16_t offset); //call the above two functions

int extract_outer_ipv6_header(struct rte_mbuf *pkt, void *hdr, uint16_t offset)
{

	struct dp_flow *df;
	struct rte_ipv6_hdr *ipv6_hdr = NULL;

	df = get_dp_flow_ptr(pkt);

	if (hdr != NULL)
	{
		ipv6_hdr = (struct rte_ipv6_hdr *)hdr;
	}
	else
	{
		ipv6_hdr = rte_pktmbuf_mtod_offset(pkt, struct rte_ipv6_hdr *, offset);
	}

	if (ipv6_hdr != NULL)
	{
		rte_memcpy(df->tun_info.ul_src_addr6, ipv6_hdr->src_addr, sizeof(df->tun_info.ul_src_addr6));
		rte_memcpy(df->tun_info.ul_dst_addr6, ipv6_hdr->dst_addr, sizeof(df->tun_info.ul_dst_addr6));
		df->tun_info.proto_id = ipv6_hdr->proto;
		// printf("ipv6->proto %#x \n",ipv6_hdr->proto);
		// printf("ipv6->hop_limits %#x \n",ipv6_hdr->hop_limits);
		// printf("payload length in arriving ipv6 hdr %#x \n",ipv6_hdr->payload_len);
		return ipv6_hdr->proto;
	}

	return -1;
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

	if (src)
	{
		memcpy(&(eth_spec->src), src, nr_src_mask_len);
		memcpy(&(eth_mask->src), ether_addr_mask, nr_src_mask_len);
	}

	if (dst)
	{
		memcpy(&(eth_spec->src), src, nr_dst_mask_len);
		memcpy(&(eth_mask->src), ether_addr_mask, nr_dst_mask_len);
	}

	eth_spec->type = type;
	eth_mask->type = htons(0xffff);

	pattern[pattern_cnt].type = RTE_FLOW_ITEM_TYPE_ETH;
	pattern[pattern_cnt].spec = eth_spec;
	pattern[pattern_cnt].mask = eth_mask;

	return pattern_cnt++;
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

	if (src)
	{
		memcpy(ipv6_spec->hdr.src_addr, src, nr_src_mask_len);
		memcpy(ipv6_mask->hdr.src_addr, ipv6_addr_mask, nr_src_mask_len);
	}

	if (dst)
	{
		memcpy(ipv6_spec->hdr.dst_addr, dst, nr_dst_mask_len);
		memcpy(ipv6_mask->hdr.dst_addr, ipv6_addr_mask, nr_dst_mask_len);
	}

	ipv6_spec->hdr.proto = proto;
	ipv6_mask->hdr.proto = 0xff;

	pattern[pattern_cnt].type = RTE_FLOW_ITEM_TYPE_IPV6;
	pattern[pattern_cnt].spec = ipv6_spec;
	pattern[pattern_cnt].mask = ipv6_mask;

	return pattern_cnt++;
}
