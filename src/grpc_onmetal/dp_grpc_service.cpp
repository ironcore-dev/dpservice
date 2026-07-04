// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#include "grpc_onmetal/dp_grpc_service.hpp"
#include "grpc_onmetal/dp_async_grpc.hpp"


GRPCServiceOnmetal* GRPCServiceOnmetal::instance = nullptr;

GRPCServiceOnmetal* GRPCServiceOnmetal::GetInstance()
{
	if (!instance)
		instance = new GRPCServiceOnmetal();
	return instance;
}

void GRPCServiceOnmetal::Cleanup()
{
	if (!instance)
		return;
	delete instance;
	instance = nullptr;
}


void GRPCServiceOnmetal::InitRpcs()
{
	new InitializeCallOnmetal();
	new CheckInitializedCallOnmetal();
	new DeletePrefixCallOnmetal();
	new ListPrefixesCallOnmetal();
	new CreatePrefixCallOnmetal();
	new ListLoadBalancerTargetsCallOnmetal();
	new CreateLoadBalancerTargetCallOnmetal();
	new DeleteLoadBalancerTargetCallOnmetal();
	new CreateVipCallOnmetal();
	new DeleteVipCallOnmetal();
	new GetVipCallOnmetal();
	new CreateRouteCallOnmetal();
	new DeleteRouteCallOnmetal();
	new ListRoutesCallOnmetal();
	new CreateInterfaceCallOnmetal();
	new DeleteInterfaceCallOnmetal();
	new ListInterfacesCallOnmetal();
	new GetInterfaceCallOnmetal();
	new CreateLoadBalancerCallOnmetal();
	new GetLoadBalancerCallOnmetal();
	new ListLoadBalancersCallOnmetal();
	new DeleteLoadBalancerCallOnmetal();
	new CreateNatCallOnmetal();
	new GetNatCallOnmetal();
	new DeleteNatCallOnmetal();
	new CreateNeighborNatCallOnmetal();
	new DeleteNeighborNatCallOnmetal();
	new ListLocalNatsCallOnmetal();
	new ListNeighborNatsCallOnmetal();
	new ListLoadBalancerPrefixesCallOnmetal();
	new DeleteLoadBalancerPrefixCallOnmetal();
	new CreateLoadBalancerPrefixCallOnmetal();
	new CreateFirewallRuleCallOnmetal();
	new GetFirewallRuleCallOnmetal();
	new DeleteFirewallRuleCallOnmetal();
	new ListFirewallRulesCallOnmetal();
	new CheckVniInUseCallOnmetal();
	new ResetVniCallOnmetal();
	new GetVersionCallOnmetal();
	new CaptureStartCallOnmetal();
	new CaptureStopCallOnmetal();
	new CaptureStatusCallOnmetal();
}
