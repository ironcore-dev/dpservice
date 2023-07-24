#ifndef __INCLUDE_DP_GRPC_FWALL_H__
#define __INCLUDE_DP_GRPC_FWALL_H__

#include "../dp_firewall.h"
#include "dp_grpc_api.h"
#include "../proto/dpdk.pb.h"

using namespace dpdkonmetal::v1;

namespace GrpcConv
{
	Status* CreateStatus(uint32_t grpc_errcode);

	bool StrToIpv4(const std::string& str, uint32_t *dst);
	bool StrToIpv6(const std::string& str, uint8_t *dst);

	bool GrpcToDpAddress(const IpAddress& grpc_addr, struct dpgrpc_address *dp_addr);

	bool GrpcToDpVniType(const VniType& grpc_type, enum dpgrpc_vni_type *dp_type);

	bool GrpcToDpFwallAction(const FirewallAction& grpc_action, enum dp_fwall_action *dp_action);
	bool GrpcToDpFwallDirection(const TrafficDirection& grpc_dir, enum dp_fwall_direction *dp_dir);

	uint32_t Ipv4PrefixLenToMask(uint32_t prefix_length);

	void DpToGrpcInterface(const struct dpgrpc_iface *dp_iface, Interface *grpc_iface);

	void DpToGrpcFwrule(const struct dp_fwall_rule *dp_rule, FirewallRule *grpc_rule);
}

#endif
