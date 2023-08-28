#include "rte_flow/dp_rte_flow.h"
#include "dp_error.h"
#include "dp_flow.h"
#include "dp_lpm.h"
#include "dp_mbuf_dyn.h"
#include "dp_nat.h"
#include "nodes/dhcp_node.h"
#include "nodes/ipv6_nd_node.h"

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


struct rte_flow *dp_install_rte_flow(uint16_t port_id,
									 const struct rte_flow_attr *attr,
									 const struct rte_flow_item pattern[],
									 const struct rte_flow_action actions[])
{
	int ret;
	struct rte_flow *flow;
	struct rte_flow_error error;

	ret = rte_flow_validate(port_id, attr, pattern, actions, &error);
	if (DP_FAILED(ret)) {
		DPS_LOG_ERR("Flow cannot be validated", DP_LOG_PORTID(port_id),  DP_LOG_FLOW_ERROR(error.message), DP_LOG_RET(ret));
		return NULL;
	}

	flow = rte_flow_create(port_id, attr, pattern, actions, &error);
	if (!flow) {
		DPS_LOG_ERR("Flow cannot be created", DP_LOG_PORTID(port_id), DP_LOG_FLOW_ERROR(error.message));
		return NULL;
	}
	return flow;
}
