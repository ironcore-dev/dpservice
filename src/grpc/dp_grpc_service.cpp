#include "grpc/dp_grpc_service.h"
#include "grpc/dp_async_grpc.h"
#include "dp_lpm.h"
#include "dp_port.h"
#include "dpdk_layer.h"
#include <rte_mbuf.h>
#include "dp_log.h"
#include "dp_timers.h"


GRPCService::GRPCService()
{
	uuid = malloc(DP_UUID_SIZE);
	uuid_generate_random(binuuid);
	uuid_unparse_upper(binuuid, (char*)uuid);
}

GRPCService::~GRPCService()
{
	free(uuid);
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

char* GRPCService::GetUUID()
{
	return (char*)uuid;
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

	new InitializeCall(this, cq_.get());
	new CheckInitializedCall(this, cq_.get());
	new DeletePrefixCall(this, cq_.get());
	new ListPrefixesCall(this, cq_.get());
	new CreatePrefixCall(this, cq_.get());
	new ListLoadBalancerTargetsCall(this, cq_.get());
	new CreateLoadBalancerTargetCall(this, cq_.get());
	new DeleteLoadBalancerTargetCall(this, cq_.get());
	new CreateVIPCall(this, cq_.get());
	new DeleteVIPCall(this, cq_.get());
	new GetVIPCall(this, cq_.get());
	new CreateRouteCall(this, cq_.get());
	new DeleteRouteCall(this, cq_.get());
	new ListRoutesCall(this, cq_.get());
	new CreateInterfaceCall(this, cq_.get());
	new DeleteInterfaceCall(this, cq_.get());
	new ListInterfacesCall(this, cq_.get());
	new GetInterfaceCall(this, cq_.get());
	new CreateLoadBalancerCall(this, cq_.get());
	new GetLoadBalancerCall(this, cq_.get());
	new DeleteLoadBalancerCall(this, cq_.get());
	new CreateNATCall(this, cq_.get());
	new GetNATCall(this, cq_.get());
	new DeleteNATCall(this, cq_.get());
	new CreateNeighborNATCall(this, cq_.get());
	new DeleteNeighborNATCall(this, cq_.get());
	new ListLocalNATsCall(this, cq_.get());
	new ListNeighborNATsCall(this, cq_.get());
	new ListLoadBalancerPrefixesCall(this, cq_.get());
	new DeleteLoadBalancerPrefixCall(this, cq_.get());
	new CreateLoadBalancerPrefixCall(this, cq_.get());
	new CreateFirewallRuleCall(this, cq_.get());
	new GetFirewallRuleCall(this, cq_.get());
	new DeleteFirewallRuleCall(this, cq_.get());
	new ListFirewallRulesCall(this, cq_.get());
	new CheckVniInUseCall(this, cq_.get());
	new ResetVniCall(this, cq_.get());
	new GetVersionCall(this, cq_.get());

	while (true) {
		GPR_ASSERT(cq_->Next(&tag, &ok));
		GPR_ASSERT(ok);
		while (static_cast<BaseCall*>(tag)->Proceed() < 0) {};
	}
}

