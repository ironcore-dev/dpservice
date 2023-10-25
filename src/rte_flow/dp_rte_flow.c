#include "rte_flow/dp_rte_flow.h"
#include "dp_error.h"
#include "dp_flow.h"
#include "dp_lpm.h"
#include "dp_mbuf_dyn.h"
#include "dp_nat.h"
#include "nodes/dhcp_node.h"
#include "nodes/ipv6_nd_node.h"

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
