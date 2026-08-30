// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#ifndef __INCLUDE_DP_GRPC_FWALL_H__
#define __INCLUDE_DP_GRPC_FWALL_H__

#include "../dp_firewall.h"
#include "dp_grpc_api.h"
#include "../proto/dpdk.pb.h"

using namespace dpdkironcore::v1;

namespace GrpcConv
{
	Status* CreateStatus(uint32_t grpc_errcode);

	bool IsInterfaceIdValid(const std::string& id);

	bool StrToIpv4(const std::string& str, uint32_t *dst);
	bool StrToIpv6(const std::string& str, union dp_ipv6 *dst);

	bool StrToDpAddress(const std::string& str, struct dp_ip_address *dp_addr, IpVersion ipver);
	bool GrpcToDpAddress(const IpAddress& grpc_addr, struct dp_ip_address *dp_addr);

	bool StrToPreferredUnderlay(const std::string& str, union dp_ipv6 *dst);

	bool GrpcToDpVniType(const VniType& grpc_type, enum dpgrpc_vni_type *dp_type);

	bool GrpcToDpFwallAction(const FirewallAction& grpc_action, enum dp_fwall_action *dp_action);
	bool GrpcToDpFwallDirection(const TrafficDirection& grpc_dir, enum dp_fwall_direction *dp_dir);
	bool GrpcToDpFwallPort(int32_t grpc_port, uint32_t *dp_port);

	bool GrpcToDpIpsecDir(const TrafficDirection& grpc_dir, enum dp_ipsec_dir *dp_dir);
	TrafficDirection IpsecDirToGrpc(enum dp_ipsec_dir dp_dir);

	bool GrpcToDpIpsecAlgo(const IpsecAlgorithm& grpc_algo, enum dp_ipsec_algo *dp_algo);
	IpsecAlgorithm IpsecAlgoToGrpc(enum dp_ipsec_algo dp_algo);

	// Key material crosses the API hex-encoded, like the addresses cross it as strings
	bool HexToBytes(const std::string& str, uint8_t *dst, size_t len);
	std::string BytesToHex(const uint8_t *src, size_t len);

	bool GrpcToDpCaptureInterfaceType(const CaptureInterfaceType & grpc_type, enum dpgrpc_capture_iface_type *dp_capture_iface_type);
	CaptureInterfaceType CaptureInterfaceTypeToGrpc(enum dpgrpc_capture_iface_type dp_capture_iface_type);

	bool Ipv4PrefixLenToMask(uint32_t prefix_length, struct dp_ip_mask *mask);

	bool Ipv6PrefixLenToMask(uint32_t prefix_length, struct dp_ip_mask *mask);

	void DpToGrpcAddress(const struct dp_ip_address *dp_addr, IpAddress *grpc_addr);

	void DpToGrpcInterface(const struct dpgrpc_iface *dp_iface, Interface *grpc_iface);

	void DpToGrpcLoadBalancer(const struct dpgrpc_lb *dp_lb, Loadbalancer *grpc_lb);

	void DpToGrpcFwrule(const struct dp_fwall_rule *dp_rule, FirewallRule *grpc_rule);
}

#endif
