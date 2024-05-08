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
	if (DP_FAILED(dp_str_to_ipv4(str.c_str(), dst)))
		return false;

	return true;
}

bool StrToIpv6(const std::string& str, union dp_ipv6 *dst)
{
	if (DP_FAILED(dp_str_to_ipv6(str.c_str(), dst)))
		return false;

	return true;
}

bool StrToDpAddress(const std::string& str, struct dp_ip_address *dp_addr, IpVersion ipver)
{
	uint32_t ipv4;
	union dp_ipv6 ipv6 = {{0},};  // C++ tries to use deleted default constructor otherwise

	switch (ipver) {
	case IpVersion::IPV4:
		if (!StrToIpv4(str, &ipv4))
			return false;
		dp_set_ipaddr4(dp_addr, ipv4);
		return true;
	case IpVersion::IPV6:
		if (!StrToIpv6(str, &ipv6))
			return false;
		dp_set_ipaddr6(dp_addr, &ipv6);
		return true;
	default:
		return false;
	}
}

bool GrpcToDpAddress(const IpAddress& grpc_addr, struct dp_ip_address *dp_addr)
{
	return StrToDpAddress(grpc_addr.address(), dp_addr, grpc_addr.ipver());
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

bool Ipv4PrefixLenToMask(uint32_t prefix_length, struct dp_ip_mask *mask)
{
	if (prefix_length > 32)
		return false;

	if (prefix_length == DP_FWALL_MATCH_ANY_LENGTH)
		mask->ip4 = DP_FWALL_MATCH_ANY_LENGTH;
	else
		mask->ip4 = ~((1 << (32 - prefix_length)) - 1);

	return true;
}

bool Ipv6PrefixLenToMask(uint32_t prefix_length, struct dp_ip_mask *mask)
{
	if (prefix_length > 128)
		return false;

	uint8_t ipv6[DP_IPV6_ADDR_SIZE] = { 0, };

	for (uint32_t i = 0; i < prefix_length; i++) {
		ipv6[i / 8] |= (uint8_t)(1 << (7 - (i % 8)));
	}

	DP_IPV6_FROM_ARRAY(&mask->ip6, ipv6);
	return true;
}


void DpToGrpcAddress(const struct dp_ip_address *dp_addr, IpAddress *grpc_addr)
{
	char strbuf[INET6_ADDRSTRLEN];

	DP_IPADDR_TO_STR(dp_addr, strbuf);
	grpc_addr->set_address(strbuf);
	grpc_addr->set_ipver(dp_addr->is_v6 ? IpVersion::IPV6 : IpVersion::IPV4);
}

void DpToGrpcInterface(const struct dpgrpc_iface *dp_iface, Interface *grpc_iface)
{
	char strbuf[INET6_ADDRSTRLEN];
	MeteringParams *metering_params;

	DP_IPV4_TO_STR(dp_iface->ip4_addr, strbuf);
	grpc_iface->set_primary_ipv4(strbuf);
	DP_IPV6_TO_STR(&dp_iface->ip6_addr, strbuf);
	grpc_iface->set_primary_ipv6(strbuf);
	grpc_iface->set_id(dp_iface->iface_id);
	grpc_iface->set_vni(dp_iface->vni);
	grpc_iface->set_pci_name(dp_iface->pci_name);
	DP_IPV6_TO_STR(&dp_iface->ul_addr6, strbuf);
	grpc_iface->set_underlay_route(strbuf);
	metering_params = new MeteringParams();
	metering_params->set_total_rate(dp_iface->total_flow_rate_cap);
	metering_params->set_public_rate(dp_iface->public_flow_rate_cap);
	grpc_iface->set_allocated_meteringparams(metering_params);
}

static void SetupIpAndPrefix(const struct dp_fwall_rule *dp_rule, IpAddress* ip, Prefix* pfx, bool is_source)
{
	auto& rule_ip = is_source ? dp_rule->src_ip : dp_rule->dest_ip;
	auto& rule_mask = is_source ? dp_rule->src_mask : dp_rule->dest_mask;

	// NOTE: This assumes the mask is valid (i.e. starting from the left, no holes)
	GrpcConv::DpToGrpcAddress(&rule_ip, ip);
	if (!rule_ip.is_v6)
		pfx->set_length(dp_ipv6_popcount(&rule_mask.ip6));
	else
		pfx->set_length(__builtin_popcount(rule_mask.ip4));
	pfx->set_allocated_ip(ip);
}

void DpToGrpcFwrule(const struct dp_fwall_rule *dp_rule, FirewallRule *grpc_rule)
{
	constexpr bool IS_SRC = true;
	constexpr bool IS_DST = false;
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
	src_pfx = new Prefix();
	SetupIpAndPrefix(dp_rule, src_ip, src_pfx, IS_SRC);
	grpc_rule->set_allocated_source_prefix(src_pfx);

	dst_ip = new IpAddress();
	dst_pfx = new Prefix();
	SetupIpAndPrefix(dp_rule, dst_ip, dst_pfx, IS_DST);
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
