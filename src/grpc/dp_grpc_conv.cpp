// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#include "grpc/dp_grpc_conv.h"
#include "dp_error.h"
#include "dp_log.h"

namespace GrpcConv {

Status* CreateStatus(uint32_t grpc_errcode)
{
	Status* err_status = new Status();
	err_status->set_code(grpc_errcode);
	err_status->set_message(dp_grpc_strerror(grpc_errcode));
	return err_status;
}

bool IsInterfaceIdValid(const std::string& id)
{
	for (std::string::const_iterator i = id.begin(); i != id.end(); ++i) {
		char c = *i;
		// alphanumeric and underscore (allowed by standard DPDK) and '-' for GUID (dp-service extension)
		if (!(c == '-' || c == '_' || (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')))
			return false;
	}
	return true;
}

bool StrToIpv4(const std::string& str, uint32_t *dst)
{
	struct in_addr addr;

	// man(3) inet_aton: 'inet_aton() returns nonzero if the address is valid, zero if not.'
	if (inet_aton(str.c_str(), &addr) == 0)
		return false;

	*dst = ntohl(addr.s_addr);
	return true;
}

bool StrToIpv6(const std::string& str, uint8_t *dst)
{
	// man(3) inet_pton: 'inet_pton() returns 1 on success ...'
	return inet_pton(AF_INET6, str.c_str(), dst) == 1;
}

bool GrpcToDpAddress(const IpAddress& grpc_addr, struct dp_ip_address *dp_addr)
{
	switch (grpc_addr.ipver()) {
	case IpVersion::IPV4:
		dp_addr->ip_type = RTE_ETHER_TYPE_IPV4;
		return StrToIpv4(grpc_addr.address(), &dp_addr->ipv4);
	case IpVersion::IPV6:
		dp_addr->ip_type = RTE_ETHER_TYPE_IPV6;
		return StrToIpv6(grpc_addr.address(), dp_addr->ipv6);
	default:
		return false;
	}
}

bool GrpcToDpVniType(const VniType& grpc_type, enum dpgrpc_vni_type *dp_type)
{
	switch (grpc_type) {
	case VniType::VNI_IPV4:
		*dp_type = DP_VNI_IPV4;
		return true;
	case VniType::VNI_IPV6:
		*dp_type = DP_VNI_IPV6;
		return true;
	case VniType::VNI_BOTH:
		*dp_type = DP_VNI_BOTH;
		return true;
	default:
		return false;
	}
}

bool GrpcToDpFwallAction(const FirewallAction& grpc_action, enum dp_fwall_action *dp_action)
{
	switch (grpc_action) {
	case FirewallAction::ACCEPT:
		*dp_action = DP_FWALL_ACCEPT;
		return true;
	case FirewallAction::DROP:
		*dp_action = DP_FWALL_DROP;
		return true;
	default:
		return false;
	}
}

bool GrpcToDpFwallDirection(const TrafficDirection& grpc_dir, enum dp_fwall_direction *dp_dir)
{
	switch (grpc_dir) {
	case TrafficDirection::INGRESS:
		*dp_dir = DP_FWALL_INGRESS;
		return true;
	case TrafficDirection::EGRESS:
		*dp_dir = DP_FWALL_EGRESS;
		return true;
	default:
		return false;
	}
}

bool GrpcToDpFwallPort(int32_t grpc_port, uint32_t *dp_port)
{
	uint32_t port = (uint32_t)grpc_port;

	if (port != DP_FWALL_MATCH_ANY_PORT && port > UINT16_MAX)
		return false;
	*dp_port = port;
	return true;
}

bool GrpcToDpCaptureInterfaceType(const CaptureInterfaceType& grpc_type, enum dpgrpc_capture_iface_type *dp_capture_iface_type)
{
	switch (grpc_type) {
	case CaptureInterfaceType::SINGLE_PF:
		*dp_capture_iface_type = DP_CAPTURE_IFACE_TYPE_SINGLE_PF;
		return true;
	case CaptureInterfaceType::SINGLE_VF:
		*dp_capture_iface_type = DP_CAPTURE_IFACE_TYPE_SINGLE_VF;
		return true;
	default:
		return false;
	}
}

bool DpCaptureInterfaceTypeToGrpc(CaptureInterfaceType& grpc_type, enum dpgrpc_capture_iface_type dp_capture_iface_type)
{
	switch (dp_capture_iface_type) {
	case DP_CAPTURE_IFACE_TYPE_SINGLE_PF:
		grpc_type = CaptureInterfaceType::SINGLE_PF;
		return true;
	case DP_CAPTURE_IFACE_TYPE_SINGLE_VF:
		grpc_type = CaptureInterfaceType::SINGLE_VF;
		return true;
	default:
		return false;
	}
}

const char *Ipv4ToStr(uint32_t ipv4)
{
	struct in_addr addr = {
		.s_addr = htonl(ipv4)
	};

	// cannot fail, the range is known and fully defined and the buffer is static
	return inet_ntoa(addr);
}

bool Ipv4PrefixLenToMask(uint32_t prefix_length, uint32_t *mask)
{
	if (prefix_length > 32)
		return false;

	if (prefix_length == DP_FWALL_MATCH_ANY_LENGTH)
		*mask = DP_FWALL_MATCH_ANY_LENGTH;
	else
		*mask = ~((1 << (32 - prefix_length)) - 1);

	return true;
}


void DpToGrpcInterface(const struct dpgrpc_iface *dp_iface, Interface *grpc_iface)
{
	char strbuf[INET6_ADDRSTRLEN];

	grpc_iface->set_primary_ipv4(GrpcConv::Ipv4ToStr(dp_iface->ip4_addr));
	inet_ntop(AF_INET6, dp_iface->ip6_addr, strbuf, sizeof(strbuf));
	grpc_iface->set_primary_ipv6(strbuf);
	grpc_iface->set_id(dp_iface->iface_id);
	grpc_iface->set_vni(dp_iface->vni);
	grpc_iface->set_pci_name(dp_iface->pci_name);
	inet_ntop(AF_INET6, dp_iface->ul_addr6, strbuf, sizeof(strbuf));
	grpc_iface->set_underlay_route(strbuf);
}

void DpToGrpcFwrule(const struct dp_fwall_rule *dp_rule, FirewallRule *grpc_rule)
{
	IcmpFilter *icmp_filter;
	ProtocolFilter *filter;
	TcpFilter *tcp_filter;
	UdpFilter *udp_filter;
	Prefix *src_pfx;
	Prefix *dst_pfx;
	IpAddress *src_ip;
	IpAddress *dst_ip;

	grpc_rule->set_id(dp_rule->rule_id);
	grpc_rule->set_priority(dp_rule->priority);
	if (dp_rule->dir == DP_FWALL_INGRESS)
		grpc_rule->set_direction(TrafficDirection::INGRESS);
	else
		grpc_rule->set_direction(TrafficDirection::EGRESS);

	if (dp_rule->action == DP_FWALL_ACCEPT)
		grpc_rule->set_action(FirewallAction::ACCEPT);
	else
		grpc_rule->set_action(FirewallAction::DROP);

	src_ip = new IpAddress();
	src_ip->set_ipver(IpVersion::IPV4);
	src_ip->set_address(GrpcConv::Ipv4ToStr(dp_rule->src_ip));
	src_pfx = new Prefix();
	src_pfx->set_allocated_ip(src_ip);
	src_pfx->set_length(__builtin_popcount(dp_rule->src_ip_mask));
	grpc_rule->set_allocated_source_prefix(src_pfx);

	dst_ip = new IpAddress();
	dst_ip->set_ipver(IpVersion::IPV4);
	dst_ip->set_address(GrpcConv::Ipv4ToStr(dp_rule->dest_ip));
	dst_pfx = new Prefix();
	dst_pfx->set_allocated_ip(dst_ip);
	dst_pfx->set_length(__builtin_popcount(dp_rule->dest_ip_mask));
	grpc_rule->set_allocated_destination_prefix(dst_pfx);

	filter = new ProtocolFilter();
	switch (dp_rule->protocol) {
	case IPPROTO_TCP:
		tcp_filter = new TcpFilter();
		tcp_filter->set_dst_port_lower(dp_rule->filter.tcp_udp.dst_port.lower);
		tcp_filter->set_dst_port_upper(dp_rule->filter.tcp_udp.dst_port.upper);
		tcp_filter->set_src_port_lower(dp_rule->filter.tcp_udp.src_port.lower);
		tcp_filter->set_src_port_upper(dp_rule->filter.tcp_udp.src_port.upper);
		filter->set_allocated_tcp(tcp_filter);
		break;
	case IPPROTO_UDP:
		udp_filter = new UdpFilter();
		udp_filter->set_dst_port_lower(dp_rule->filter.tcp_udp.dst_port.lower);
		udp_filter->set_dst_port_upper(dp_rule->filter.tcp_udp.dst_port.upper);
		udp_filter->set_src_port_lower(dp_rule->filter.tcp_udp.src_port.lower);
		udp_filter->set_src_port_upper(dp_rule->filter.tcp_udp.src_port.upper);
		filter->set_allocated_udp(udp_filter);
		break;
	case IPPROTO_ICMP:
		icmp_filter = new IcmpFilter();
		icmp_filter->set_icmp_code(dp_rule->filter.icmp.icmp_code);
		icmp_filter->set_icmp_type(dp_rule->filter.icmp.icmp_type);
		filter->set_allocated_icmp(icmp_filter);
		break;
	}
	grpc_rule->set_allocated_protocol_filter(filter);
}

}  // namespace GrpcConversion
