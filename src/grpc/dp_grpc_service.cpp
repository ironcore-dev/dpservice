#include "grpc/dp_grpc_service.h"
#include "grpc/dp_async_grpc.h"
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
	this->cq_ = builder.AddCompletionQueue();
	this->server_ = builder.BuildAndStart();
	if (this->server_ == nullptr) {
		DPGRPC_LOG_ERR("Server failed to start", _DP_LOG_STR("grpc_server_address", listen_address.c_str()));
		return false;
	}

	DPGRPC_LOG_INFO("Server started and listening", _DP_LOG_STR("grpc_server_address", listen_address.c_str()));
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

	while (true) {
		GPR_ASSERT(cq_->Next(&tag, &ok));
		GPR_ASSERT(ok);
		while (static_cast<BaseCall*>(tag)->Proceed() < 0) {};
	}
}

