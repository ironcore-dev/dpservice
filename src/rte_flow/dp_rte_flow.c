#include "rte_flow/dp_rte_flow.h"
#include "dp_flow.h"
#include "dp_lpm.h"
#include "dp_nat.h"
#include "nodes/dhcp_node.h"
#include "node_api.h"
#include "nodes/ipv6_nd_node.h"

const static uint8_t ether_addr_mask[RTE_ETHER_ADDR_LEN] = "\xff\xff\xff\xff\xff\xff";
const static uint8_t ipv6_addr_mask[16] = "\xff\xff\xff\xff\xff\xff\xff\xff"
										  "\xff\xff\xff\xff\xff\xff\xff\xff";
const static uint8_t ipv4_addr_mask[4] = "\xff\xff\xff\xff";

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

struct rte_ipv4_hdr *dp_get_ipv4_hdr(struct rte_mbuf *m)
{
	struct rte_ipv4_hdr *ipv4_hdr;
	struct dp_flow *df_ptr;

	df_ptr = get_dp_flow_ptr(m);

	if (df_ptr->flags.flow_type == DP_FLOW_TYPE_INCOMING)
		ipv4_hdr = rte_pktmbuf_mtod(m, struct rte_ipv4_hdr *);
	else
		ipv4_hdr = rte_pktmbuf_mtod_offset(m, struct rte_ipv4_hdr *,
										   sizeof(struct rte_ether_hdr));

	return ipv4_hdr;
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

	return ++pattern_cnt;
}

int insert_ipv4_match_pattern(struct rte_flow_item *pattern, int pattern_cnt,
							  struct rte_flow_item_ipv4 *ipv4_spec,
							  struct rte_flow_item_ipv4 *ipv4_mask,
							  struct dp_flow *df, bool dir)
{

	memset(ipv4_spec, 0, sizeof(struct rte_flow_item_ipv4));
	memset(ipv4_mask, 0, sizeof(struct rte_flow_item_ipv4));

	if (dir == DP_IS_SRC) {
		ipv4_spec->hdr.src_addr = df->src.src_addr;
		memcpy(&ipv4_mask->hdr.src_addr, ipv4_addr_mask, sizeof(ipv4_spec->hdr.src_addr));
	}

	if (dir == DP_IS_DST) {
		if (df->flags.nat == DP_NAT_CHG_DST_IP)
			ipv4_spec->hdr.dst_addr = df->nat_addr;
		else
			ipv4_spec->hdr.dst_addr = df->dst.dst_addr;
		memcpy(&ipv4_mask->hdr.dst_addr, ipv4_addr_mask, sizeof(ipv4_spec->hdr.dst_addr));
	}

	ipv4_spec->hdr.next_proto_id = df->l4_type;
	ipv4_mask->hdr.next_proto_id = 0xff;

	pattern[pattern_cnt].type = RTE_FLOW_ITEM_TYPE_IPV4;
	pattern[pattern_cnt].spec = ipv4_spec;
	pattern[pattern_cnt].mask = ipv4_mask;

	return ++pattern_cnt;
}

int insert_udp_match_pattern(struct rte_flow_item *pattern, int pattern_cnt,
							 struct rte_flow_item_udp *udp_spec,
							 struct rte_flow_item_udp *udp_mask,
							 uint16_t src_port, uint16_t dst_port)
{

	memset(udp_spec, 0, sizeof(struct rte_flow_item_udp));
	memset(udp_mask, 0, sizeof(struct rte_flow_item_udp));

	// Who is going to match a port that is 0? Let's assume that port>0 is a valid one.
	if (src_port)
	{
		udp_spec->hdr.src_port = src_port;
		udp_mask->hdr.src_port = 0xffff;
	}

	if (dst_port)
	{
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
							 uint16_t src_port, uint16_t dst_port)
{

	memset(tcp_spec, 0, sizeof(struct rte_flow_item_tcp));
	memset(tcp_mask, 0, sizeof(struct rte_flow_item_tcp));

	// Who is going to match a port that is 0? Let's assume that port>0 is a valid one.
	if (src_port)
	{
		tcp_spec->hdr.src_port = src_port;
		tcp_mask->hdr.src_port = 0xffff;
	}

	if (dst_port)
	{
		tcp_spec->hdr.dst_port = dst_port;
		tcp_mask->hdr.dst_port = 0xffff;
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

int insert_geneve_match_pattern(struct rte_flow_item *pattern, int pattern_cnt,
								struct rte_flow_item_geneve *geneve_spec,
								struct rte_flow_item_geneve *geneve_mask,
								uint16_t type, uint32_t *vni)
{

	memset(geneve_spec, 0, sizeof(struct rte_flow_item_geneve));
	memset(geneve_mask, 0, sizeof(struct rte_flow_item_geneve));

	geneve_spec->protocol = htons(type);
	geneve_mask->protocol = 0xFFFF;

	uint8_t vni_mask[3] = {0xFF, 0xFF, 0xFF};
	rte_memcpy(geneve_spec->vni, vni, sizeof(geneve_spec->vni));
	rte_memcpy(geneve_mask->vni, vni_mask, sizeof(geneve_spec->vni));

	pattern[pattern_cnt].type = RTE_FLOW_ITEM_TYPE_GENEVE;
	pattern[pattern_cnt].spec = geneve_spec;
	pattern[pattern_cnt].mask = geneve_mask;

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
						   uint32_t ipv4, bool dir)
{
	ipv4_action->ipv4_addr = ipv4;

	if (dir == DP_IS_DST)
		action[action_cnt].type = RTE_FLOW_ACTION_TYPE_SET_IPV4_DST;
	else
		action[action_cnt].type = RTE_FLOW_ACTION_TYPE_SET_IPV4_SRC;

	action[action_cnt].conf = ipv4_action;

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

int create_end_action(struct rte_flow_action *action, int action_cnt)
{

	action[action_cnt].type = RTE_FLOW_ACTION_TYPE_END;
	return ++action_cnt;
}

// flow aging related config is highly customized, thus put them into a function in case different agectx needs
// to be configured
void free_allocated_agectx(struct flow_age_ctx *agectx)
{
	if (agectx)
		rte_free(agectx);
}

void config_allocated_agectx(struct flow_age_ctx *agectx, uint16_t port_id,
							struct dp_flow *df, struct rte_flow *flow)
{

	agectx->cntrack = df->conntrack;
	agectx->dir = agectx->cntrack->dir;
	agectx->cntrack->rteflow[agectx->dir] = flow;
	agectx->cntrack->port = port_id;
	rte_atomic32_inc(&agectx->cntrack->flow_cnt);
}

struct rte_flow *validate_and_install_rte_flow(uint16_t port_id,
												const struct rte_flow_attr *attr,
												const struct rte_flow_item pattern[],
												const struct rte_flow_action action[],
												struct dp_flow *df)
{

	int res;
	struct rte_flow *flow = NULL;

	struct rte_flow_error error;
	res = rte_flow_validate(port_id, attr, pattern, action, &error);

	if (res)
	{
		printf("Flow can't be validated message: %s\n", error.message ? error.message : "(no stated reason)");
		return NULL;
	}
	else
	{
		printf("Flow validated on port %d targeting port %d \n ", port_id, df->nxt_hop);
		flow = rte_flow_create(port_id, attr, pattern, action, &error);
		if (!flow)
		{
			printf("Flow can't be created message: %s\n", error.message ? error.message : "(no stated reason)");
			return NULL;
		}
		return flow;
	}
}