// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#include "grpc/dp_grpc_service.hpp"
#include "grpc/dp_async_grpc.hpp"
#include "dp_lpm.h"
#include "dp_port.h"
#include "dpdk_layer.h"
#include <rte_mbuf.h>
#include "dp_log.h"
#include "dp_timers.h"


GRPCService* GRPCService::instance = nullptr;

GRPCService* GRPCService::GetInstance()
{
	if (!instance)
		instance = new GRPCService();
	return instance;
}

void GRPCService::Cleanup()
{
	if (!instance)
		return;
	delete instance;
	instance = nullptr;
}

GRPCService::GRPCService()
{
	uuid = new char[DP_UUID_SIZE];
	uuid_generate_random(binuuid);
	uuid_unparse_upper(binuuid, uuid);
}

GRPCService::~GRPCService()
{
	delete uuid;
}


bool GRPCService::run(std::string listen_address)
{
	ServerBuilder builder;
	builder.AddListeningPort(listen_address, grpc::InsecureServerCredentials());
	builder.RegisterService(this);

	health_service_.reset(new HealthService);
	builder.RegisterService(health_service_.get());

	// since health service supports permanent connections,
	// set a keepalive similar to the one golang default implementation uses (as observed by tcpdump)
	builder.SetOption(grpc::MakeChannelArgumentOption(GRPC_ARG_KEEPALIVE_TIME_MS, 15000));

	this->cq_ = builder.AddCompletionQueue();
	this->server_ = builder.BuildAndStart();
	if (this->server_ == nullptr) {
		DPGRPC_LOG_ERR("Server failed to start", _DP_LOG_STR("grpc_server_address", listen_address.c_str()));
		return false;
	}

	DPGRPC_LOG_INFO("Server started and listening", _DP_LOG_STR("grpc_server_address", listen_address.c_str()));
	setHealthy(true);

	HandleRpcs();
	return true;
}

const char* GRPCService::GetUUID()
{
	return uuid;
}

void GRPCService::SetInitStatus(bool status)
{
	dp_timers_signal_initialization();
	initialized = status;
}

bool GRPCService::IsInitialized()
{
	return initialized;
}

void GRPCService::HandleRpcs()
{
	BaseCall* call;
	void* tag;
	bool ok;

	new InitializeCall();
	new CheckInitializedCall();
	new DeletePrefixCall();
	new ListPrefixesCall();
	new CreatePrefixCall();
	new ListLoadBalancerTargetsCall();
	new CreateLoadBalancerTargetCall();
	new DeleteLoadBalancerTargetCall();
	new CreateVipCall();
	new DeleteVipCall();
	new GetVipCall();
	new CreateRouteCall();
	new DeleteRouteCall();
	new ListRoutesCall();
	new CreateInterfaceCall();
	new DeleteInterfaceCall();
	new ListInterfacesCall();
	new GetInterfaceCall();
	new CreateLoadBalancerCall();
	new GetLoadBalancerCall();
	new ListLoadBalancersCall();
	new DeleteLoadBalancerCall();
	new CreateNatCall();
	new GetNatCall();
	new DeleteNatCall();
	new CreateNeighborNatCall();
	new DeleteNeighborNatCall();
	new ListLocalNatsCall();
	new ListNeighborNatsCall();
	new ListLoadBalancerPrefixesCall();
	new DeleteLoadBalancerPrefixCall();
	new CreateLoadBalancerPrefixCall();
	new CreateFirewallRuleCall();
	new GetFirewallRuleCall();
	new DeleteFirewallRuleCall();
	new ListFirewallRulesCall();
	new CheckVniInUseCall();
	new ResetVniCall();
	new GetVersionCall();
	new CaptureStartCall();
	new CaptureStopCall();
	new CaptureStatusCall();

	while (cq_->Next(&tag, &ok) && ok) {
		call = static_cast<BaseCall*>(tag);
		while (call->HandleRpc() == CallState::AWAIT_MSG) {
			// wait for response from worker
		};
	}
	DPGRPC_LOG_ERR("gRPC internal error (cannot read next message)");
	rte_exit(EXIT_FAILURE, "gRPC service aborted\n");
}

void GRPCService::setHealthy(bool state)
{
	health_service_->SetServingStatus(state
		? grpc::health::v1::HealthCheckResponse::SERVING
		: grpc::health::v1::HealthCheckResponse::NOT_SERVING);
}

extern "C" void dp_grpc_service_set_healthy(bool state)
{
	GRPCService::GetInstance()->setHealthy(state);
}
