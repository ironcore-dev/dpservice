#ifndef __INCLUDE_DP_ASYNC_GRPC_H__
#define __INCLUDE_DP_ASYNC_GRPC_H__

#include "../proto/dpdk.grpc.pb.h"


#include <grpc/grpc.h>
#include <grpcpp/security/server_credentials.h>
#include <grpcpp/server.h>
#include <grpcpp/server_builder.h>
#include <grpcpp/server_context.h>
#include "dp_error.h"
#include "dp_grpc_api.h"
#include "dp_firewall.h"

using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::ServerReader;
using grpc::ServerReaderWriter;
using grpc::ServerWriter;

using grpc::ServerAsyncResponseWriter;
using grpc::ServerCompletionQueue;

using namespace dpdkonmetal::v1;

#include "dp_grpc_service.h"

enum CallStatus { REQUEST, INITCHECK, AWAIT_MSG, FINISH };

class BaseCall {
protected:
	grpc::Status ret = grpc::Status::OK;
	// TODO maybe some std::pointer stuff here?
	GRPCService* service_;
	ServerCompletionQueue* cq_;
	CallStatus status_;
	dpgrpc_request_type call_type_;
	ServerContext ctx_;
	static Status *CreateErrStatus(dpgrpc_reply *reply);
public:
	BaseCall(dpgrpc_request_type call_type)
		: service_(GRPCService::GetInstance()), cq_(service_->GetCq()), status_(REQUEST), call_type_(call_type) {
		}
	int InitCheck();
	static void ConvertDPFWallRuleToGRPCFwallRule(struct dp_fwall_rule *dp_rule, FirewallRule * grpc_rule);
	static void ConvertGRPCFwallRuleToDPFWallRule(const FirewallRule * grpc_rule, struct dp_fwall_rule *dp_rule);
	virtual int Proceed() = 0;
	virtual ~BaseCall() = default;
};

class CreateLoadBalancerPrefixCall final : BaseCall {
	CreateLoadBalancerPrefixRequest request_;
	CreateLoadBalancerPrefixResponse reply_;
	ServerAsyncResponseWriter<CreateLoadBalancerPrefixResponse> responder_;

public:
	CreateLoadBalancerPrefixCall()
	: BaseCall(DP_REQ_TYPE_CREATE_LBPREFIX), responder_(&ctx_) {
		service_->RequestCreateLoadBalancerPrefix(&ctx_, &request_, &responder_, cq_, cq_,
														   this);
	}
	int Proceed() override;
};

class CheckVniInUseCall final : BaseCall {
	CheckVniInUseRequest request_;
	CheckVniInUseResponse reply_;
	ServerAsyncResponseWriter<CheckVniInUseResponse> responder_;

public:
	CheckVniInUseCall()
	: BaseCall(DP_REQ_TYPE_CHECK_VNIINUSE), responder_(&ctx_) {
		service_->RequestCheckVniInUse(&ctx_, &request_, &responder_, cq_, cq_,
														   this);
	}
	int Proceed() override;
};

class ResetVniCall final : BaseCall {
	ResetVniRequest request_;
	ResetVniResponse reply_;
	ServerAsyncResponseWriter<ResetVniResponse> responder_;

public:
	ResetVniCall()
	: BaseCall(DP_REQ_TYPE_RESET_VNI), responder_(&ctx_) {
		service_->RequestResetVni(&ctx_, &request_, &responder_, cq_, cq_,
														   this);
	}
	int Proceed() override;
};

class DeleteLoadBalancerPrefixCall final : BaseCall {
	DeleteLoadBalancerPrefixRequest request_;
	DeleteLoadBalancerPrefixResponse reply_;
	ServerAsyncResponseWriter<DeleteLoadBalancerPrefixResponse> responder_;

public:
	DeleteLoadBalancerPrefixCall()
	: BaseCall(DP_REQ_TYPE_DELETE_LBPREFIX), responder_(&ctx_) {
		service_->RequestDeleteLoadBalancerPrefix(&ctx_, &request_, &responder_, cq_, cq_,
														   this);
	}
	int Proceed() override;
};

class ListLoadBalancerPrefixesCall final : BaseCall {
	ListLoadBalancerPrefixesRequest request_;
	ListLoadBalancerPrefixesResponse reply_;
	ServerAsyncResponseWriter<ListLoadBalancerPrefixesResponse> responder_;
private:
	static void ListCallback(struct dpgrpc_reply *reply, void *context);
public:
	ListLoadBalancerPrefixesCall()
	: BaseCall(DP_REQ_TYPE_LIST_LBPREFIXES), responder_(&ctx_) {
		service_->RequestListLoadBalancerPrefixes(&ctx_, &request_, &responder_, cq_, cq_,
														   this);
	}
	int Proceed() override;
};

class CreatePrefixCall final : BaseCall {
	CreatePrefixRequest request_;
	CreatePrefixResponse reply_;
	ServerAsyncResponseWriter<CreatePrefixResponse> responder_;

public:
	CreatePrefixCall()
	: BaseCall(DP_REQ_TYPE_CREATE_PREFIX), responder_(&ctx_) {
		service_->RequestCreatePrefix(&ctx_, &request_, &responder_, cq_, cq_,
										 this);
	}
	int Proceed() override;
};

class DeletePrefixCall final : BaseCall {
	DeletePrefixRequest request_;
	DeletePrefixResponse reply_;
	ServerAsyncResponseWriter<DeletePrefixResponse> responder_;

public:
	DeletePrefixCall()
	: BaseCall(DP_REQ_TYPE_DELETE_PREFIX), responder_(&ctx_) {
		service_->RequestDeletePrefix(&ctx_, &request_, &responder_, cq_, cq_,
										 this);
	}
	int Proceed() override;
};

class ListPrefixesCall final : BaseCall {
	ListPrefixesRequest request_;
	ListPrefixesResponse reply_;
	ServerAsyncResponseWriter<ListPrefixesResponse> responder_;
private:
	static void ListCallback(struct dpgrpc_reply *reply, void *context);
public:
	ListPrefixesCall()
	: BaseCall(DP_REQ_TYPE_LIST_PREFIXES), responder_(&ctx_) {
		service_->RequestListPrefixes(&ctx_, &request_, &responder_, cq_, cq_,
										 this);
	}
	int Proceed() override;
};

class CreateVipCall final : BaseCall {
	CreateVipRequest request_;
	CreateVipResponse reply_;
	ServerAsyncResponseWriter<CreateVipResponse> responder_;

public:
	CreateVipCall()
	: BaseCall(DP_REQ_TYPE_CREATE_VIP), responder_(&ctx_) {
		service_->RequestCreateVip(&ctx_, &request_, &responder_, cq_, cq_,
										 this);
	}
	int Proceed() override;
};

class CreateLoadBalancerCall final : BaseCall {
	CreateLoadBalancerRequest request_;
	CreateLoadBalancerResponse reply_;
	ServerAsyncResponseWriter<CreateLoadBalancerResponse> responder_;

public:
	CreateLoadBalancerCall()
	: BaseCall(DP_REQ_TYPE_CREATE_LB), responder_(&ctx_) {
		service_->RequestCreateLoadBalancer(&ctx_, &request_, &responder_, cq_, cq_,
											this);
	}
	int Proceed() override;
};

class GetLoadBalancerCall final : BaseCall {
	GetLoadBalancerRequest request_;
	GetLoadBalancerResponse reply_;
	ServerAsyncResponseWriter<GetLoadBalancerResponse> responder_;

public:
	GetLoadBalancerCall()
	: BaseCall(DP_REQ_TYPE_GET_LB), responder_(&ctx_) {
		service_->RequestGetLoadBalancer(&ctx_, &request_, &responder_, cq_, cq_,
											this);
	}
	int Proceed() override;
};

class DeleteLoadBalancerCall final : BaseCall {
	DeleteLoadBalancerRequest request_;
	DeleteLoadBalancerResponse reply_;
	ServerAsyncResponseWriter<DeleteLoadBalancerResponse> responder_;

public:
	DeleteLoadBalancerCall()
	: BaseCall(DP_REQ_TYPE_DELETE_LB), responder_(&ctx_) {
		service_->RequestDeleteLoadBalancer(&ctx_, &request_, &responder_, cq_, cq_,
											this);
	}
	int Proceed() override;
};

class CreateLoadBalancerTargetCall final : BaseCall {
	CreateLoadBalancerTargetRequest request_;
	CreateLoadBalancerTargetResponse reply_;
	ServerAsyncResponseWriter<CreateLoadBalancerTargetResponse> responder_;

public:
	CreateLoadBalancerTargetCall()
	: BaseCall(DP_REQ_TYPE_CREATE_LBTARGET), responder_(&ctx_) {
		service_->RequestCreateLoadBalancerTarget(&ctx_, &request_, &responder_, cq_, cq_,
											   this);
	}
	int Proceed() override;
};

class DeleteLoadBalancerTargetCall final : BaseCall {
	DeleteLoadBalancerTargetRequest request_;
	DeleteLoadBalancerTargetResponse reply_;
	ServerAsyncResponseWriter<DeleteLoadBalancerTargetResponse> responder_;

public:
	DeleteLoadBalancerTargetCall()
	: BaseCall(DP_REQ_TYPE_DELETE_LBTARGET), responder_(&ctx_) {
		service_->RequestDeleteLoadBalancerTarget(&ctx_, &request_, &responder_, cq_, cq_,
												  this);
	}
	int Proceed() override;
};

class ListLoadBalancerTargetsCall final : BaseCall {
	ListLoadBalancerTargetsRequest request_;
	ListLoadBalancerTargetsResponse reply_;
	ServerAsyncResponseWriter<ListLoadBalancerTargetsResponse> responder_;
private:
	static void ListCallback(struct dpgrpc_reply *reply, void *context);
public:
	ListLoadBalancerTargetsCall()
	: BaseCall(DP_REQ_TYPE_LIST_LBTARGETS), responder_(&ctx_) {
		service_->RequestListLoadBalancerTargets(&ctx_, &request_, &responder_, cq_, cq_,
												this);
	}
	int Proceed() override;
};

class DeleteVipCall final : BaseCall {
	DeleteVipRequest request_;
	DeleteVipResponse reply_;
	ServerAsyncResponseWriter<DeleteVipResponse> responder_;

public:
	DeleteVipCall()
	: BaseCall(DP_REQ_TYPE_DELETE_VIP), responder_(&ctx_) {
		service_->RequestDeleteVip(&ctx_, &request_, &responder_, cq_, cq_,
										 this);
	}
	int Proceed() override;
};

class GetVipCall final : BaseCall {
	GetVipRequest request_;
	GetVipResponse reply_;
	ServerAsyncResponseWriter<GetVipResponse> responder_;

public:
	GetVipCall()
	: BaseCall(DP_REQ_TYPE_GET_VIP), responder_(&ctx_) {
		service_->RequestGetVip(&ctx_, &request_, &responder_, cq_, cq_,
										 this);
	}
	int Proceed() override;
};

class CreateInterfaceCall final : BaseCall {
	CreateInterfaceRequest request_;
	CreateInterfaceResponse reply_;
	ServerAsyncResponseWriter<CreateInterfaceResponse> responder_;

public:
	CreateInterfaceCall()
	: BaseCall(DP_REQ_TYPE_CREATE_INTERFACE), responder_(&ctx_) {
		service_->RequestCreateInterface(&ctx_, &request_, &responder_, cq_, cq_,
										 this);
	}
	int Proceed() override;
};

class DeleteInterfaceCall final : BaseCall {
	DeleteInterfaceRequest request_;
	DeleteInterfaceResponse reply_;
	ServerAsyncResponseWriter<DeleteInterfaceResponse> responder_;

public:
	DeleteInterfaceCall()
	: BaseCall(DP_REQ_TYPE_DELETE_INTERFACE), responder_(&ctx_) {
		service_->RequestDeleteInterface(&ctx_, &request_, &responder_, cq_, cq_,
										 this);
	}
	int Proceed() override;
};

class CreateRouteCall final : BaseCall {
	CreateRouteRequest request_;
	CreateRouteResponse reply_;
	ServerAsyncResponseWriter<CreateRouteResponse> responder_;

public:
	CreateRouteCall()
	: BaseCall(DP_REQ_TYPE_CREATE_ROUTE), responder_(&ctx_) {
		service_->RequestCreateRoute(&ctx_, &request_, &responder_, cq_, cq_,
										 this);
	}
	int Proceed() override;
};

class DeleteRouteCall final : BaseCall {
	DeleteRouteRequest request_;
	DeleteRouteResponse reply_;
	ServerAsyncResponseWriter<DeleteRouteResponse> responder_;

public:
	DeleteRouteCall()
	: BaseCall(DP_REQ_TYPE_DELETE_ROUTE), responder_(&ctx_) {
		service_->RequestDeleteRoute(&ctx_, &request_, &responder_, cq_, cq_,
										 this);
	}
	int Proceed() override;
};

class GetInterfaceCall final : BaseCall {
	GetInterfaceRequest request_;
	GetInterfaceResponse reply_;
	ServerAsyncResponseWriter<GetInterfaceResponse> responder_;

public:
	GetInterfaceCall()
	: BaseCall(DP_REQ_TYPE_GET_INTERFACE), responder_(&ctx_) {
		service_->RequestGetInterface(&ctx_, &request_, &responder_, cq_, cq_,
										 this);
	}
	int Proceed() override;
};

class ListRoutesCall final : BaseCall {
	ListRoutesRequest request_;
	ListRoutesResponse reply_;
	ServerAsyncResponseWriter<ListRoutesResponse> responder_;
private:
	static void ListCallback(struct dpgrpc_reply *reply, void *context);
public:
	ListRoutesCall()
	: BaseCall(DP_REQ_TYPE_LIST_ROUTES), responder_(&ctx_) {
		service_->RequestListRoutes(&ctx_, &request_, &responder_, cq_, cq_,
										 this);
	}
	int Proceed() override;
};

class ListInterfacesCall final : BaseCall {
	ListInterfacesRequest request_;
	ListInterfacesResponse reply_;
	ServerAsyncResponseWriter<ListInterfacesResponse> responder_;
private:
	static void ListCallback(struct dpgrpc_reply *reply, void *context);
public:
	ListInterfacesCall()
	: BaseCall(DP_REQ_TYPE_LIST_INTERFACES), responder_(&ctx_) {
		service_->RequestListInterfaces(&ctx_, &request_, &responder_, cq_, cq_,
										 this);
	}
	int Proceed() override;
};

class CreateNatCall final: BaseCall {
	CreateNatRequest request_;
	CreateNatResponse reply_;
	ServerAsyncResponseWriter<CreateNatResponse> responder_;

public:
	CreateNatCall()
	: BaseCall(DP_REQ_TYPE_CREATE_NAT), responder_(&ctx_) {
		service_->RequestCreateNat(&ctx_, &request_, &responder_, cq_, cq_,
										 this);
	}
	int	Proceed() override;
};

class ListLocalNatsCall final: BaseCall {
	ListLocalNatsRequest request_;
	ListLocalNatsResponse reply_;
	ServerAsyncResponseWriter<ListLocalNatsResponse> responder_;
private:
	static void ListCallback(struct dpgrpc_reply *reply, void *context);
public:
	ListLocalNatsCall()
	: BaseCall(DP_REQ_TYPE_LIST_LOCALNATS), responder_(&ctx_) {
		service_->RequestListLocalNats(&ctx_, &request_, &responder_, cq_, cq_,
										 this);
	}
	int	Proceed() override;
};

class ListNeighborNatsCall final: BaseCall {
	ListNeighborNatsRequest request_;
	ListNeighborNatsResponse reply_;
	ServerAsyncResponseWriter<ListNeighborNatsResponse> responder_;
private:
	static void ListCallback(struct dpgrpc_reply *reply, void *context);
public:
	ListNeighborNatsCall()
	: BaseCall(DP_REQ_TYPE_LIST_NEIGHNATS), responder_(&ctx_) {
		service_->RequestListNeighborNats(&ctx_, &request_, &responder_, cq_, cq_,
										 this);
	}
	int	Proceed() override;
};

class GetNatCall final: BaseCall {
	GetNatRequest request_;
	GetNatResponse reply_;
	ServerAsyncResponseWriter<GetNatResponse> responder_;

public:
	GetNatCall()
	: BaseCall(DP_REQ_TYPE_GET_NAT), responder_(&ctx_) {
		service_->RequestGetNat(&ctx_, &request_, &responder_, cq_, cq_,
								this);
	}
	int	Proceed() override;
};

class DeleteNatCall final: BaseCall {
	DeleteNatRequest request_;
	DeleteNatResponse reply_;
	ServerAsyncResponseWriter<DeleteNatResponse> responder_;

public:
	DeleteNatCall()
	: BaseCall(DP_REQ_TYPE_DELETE_NAT), responder_(&ctx_) {
		service_->RequestDeleteNat(&ctx_, &request_, &responder_, cq_, cq_,
										 this);
	}
	int	Proceed() override;
};

class CreateNeighborNatCall final: BaseCall {
	CreateNeighborNatRequest request_;
	CreateNeighborNatResponse reply_;
	ServerAsyncResponseWriter<CreateNeighborNatResponse> responder_;

public:
	CreateNeighborNatCall()
	: BaseCall(DP_REQ_TYPE_CREATE_NEIGHNAT), responder_(&ctx_) {
		service_->RequestCreateNeighborNat(&ctx_, &request_, &responder_, cq_, cq_,
										 this);
	}
	int	Proceed() override;
};

class DeleteNeighborNatCall final: BaseCall {
	DeleteNeighborNatRequest request_;
	DeleteNeighborNatResponse reply_;
	ServerAsyncResponseWriter<DeleteNeighborNatResponse> responder_;

public:
	DeleteNeighborNatCall()
	: BaseCall(DP_REQ_TYPE_DELETE_NEIGHNAT), responder_(&ctx_) {
		service_->RequestDeleteNeighborNat(&ctx_, &request_, &responder_, cq_, cq_,
										 this);
	}
	int	Proceed() override;
};

class CheckInitializedCall final : BaseCall {
	CheckInitializedRequest request_;
	CheckInitializedResponse reply_;
	ServerAsyncResponseWriter<CheckInitializedResponse> responder_;

public:
	CheckInitializedCall()
	: BaseCall(DP_REQ_TYPE_CHECK_INITIALIZED), responder_(&ctx_) {
		service_->RequestCheckInitialized(&ctx_, &request_, &responder_, cq_, cq_,
										 this);
	}
	int Proceed() override;
};

class InitializeCall final : BaseCall {
	InitializeRequest request_;
	InitializeResponse reply_;
	ServerAsyncResponseWriter<InitializeResponse> responder_;

public:
	InitializeCall()
	: BaseCall(DP_REQ_TYPE_INITIALIZE), responder_(&ctx_) {
		service_->RequestInitialize(&ctx_, &request_, &responder_, cq_, cq_,
										 this);
	}
	int Proceed() override;
};

class CreateFirewallRuleCall final : BaseCall {
	CreateFirewallRuleRequest request_;
	CreateFirewallRuleResponse reply_;
	ServerAsyncResponseWriter<CreateFirewallRuleResponse> responder_;

public:
	CreateFirewallRuleCall()
	: BaseCall(DP_REQ_TYPE_CREATE_FWRULE), responder_(&ctx_) {
		service_->RequestCreateFirewallRule(&ctx_, &request_, &responder_, cq_, cq_,
										 this);
	}
	int Proceed() override;
};

class DeleteFirewallRuleCall final : BaseCall {
	DeleteFirewallRuleRequest request_;
	DeleteFirewallRuleResponse reply_;
	ServerAsyncResponseWriter<DeleteFirewallRuleResponse> responder_;

public:
	DeleteFirewallRuleCall()
	: BaseCall(DP_REQ_TYPE_DELETE_FWRULE), responder_(&ctx_) {
		service_->RequestDeleteFirewallRule(&ctx_, &request_, &responder_, cq_, cq_,
											this);
	}
	int Proceed() override;
};

class GetFirewallRuleCall final : BaseCall {
	GetFirewallRuleRequest request_;
	GetFirewallRuleResponse reply_;
	ServerAsyncResponseWriter<GetFirewallRuleResponse> responder_;

public:
	GetFirewallRuleCall()
	: BaseCall(DP_REQ_TYPE_GET_FWRULE), responder_(&ctx_) {
		service_->RequestGetFirewallRule(&ctx_, &request_, &responder_, cq_, cq_,
										 this);
	}
	int Proceed() override;
};

class ListFirewallRulesCall final : BaseCall {
	ListFirewallRulesRequest request_;
	ListFirewallRulesResponse reply_;
	ServerAsyncResponseWriter<ListFirewallRulesResponse> responder_;
private:
	static void ListCallback(struct dpgrpc_reply *reply, void *context);
public:
	ListFirewallRulesCall()
	: BaseCall(DP_REQ_TYPE_LIST_FWRULES), responder_(&ctx_) {
		service_->RequestListFirewallRules(&ctx_, &request_, &responder_, cq_, cq_,
										 this);
	}
	int Proceed() override;
};

class GetVersionCall final : BaseCall {
	GetVersionRequest request_;
	GetVersionResponse reply_;
	ServerAsyncResponseWriter<GetVersionResponse> responder_;

public:
	GetVersionCall()
	: BaseCall(DP_REQ_TYPE_GET_VERSION), responder_(&ctx_) {
		service_->RequestGetVersion(&ctx_, &request_, &responder_, cq_, cq_,
									this);
	}
	int Proceed() override;
};

#endif //__INCLUDE_DP_ASYNC_GRPC_H__
