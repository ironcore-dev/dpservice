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

using namespace dpdkonmetal;

enum CallStatus { REQUEST, INITCHECK, AWAIT_MSG, FINISH };

class BaseCall {
protected:
	grpc::Status ret = grpc::Status::OK;
	DPDKonmetal::AsyncService* service_;
	ServerCompletionQueue* cq_;
	CallStatus status_;
	uint16_t call_type_;
	static Status *CreateErrStatus(dpgrpc_reply *reply);
public:
	BaseCall(DPDKonmetal::AsyncService* service, ServerCompletionQueue* cq, uint16_t call_type)
		: service_(service), cq_(cq), status_(REQUEST), call_type_(call_type) {
		}
	int InitCheck();
	static void ConvertDPFWallRuleToGRPCFwallRule(struct dp_fwall_rule *dp_rule, FirewallRule * grpc_rule);
	static void ConvertGRPCFwallRuleToDPFWallRule(const FirewallRule * grpc_rule, struct dp_fwall_rule *dp_rule);
	virtual int Proceed() = 0;
	virtual ~BaseCall() = default;
};

class CreateLoadBalancerPrefixCall final : BaseCall {
	ServerContext ctx_;
	CreateLoadBalancerPrefixRequest request_;
	CreateLoadBalancerPrefixResponse reply_;
	ServerAsyncResponseWriter<CreateLoadBalancerPrefixResponse> responder_;

public:
	CreateLoadBalancerPrefixCall(DPDKonmetal::AsyncService* service, ServerCompletionQueue* cq)
	: BaseCall(service, cq, DP_REQ_TYPE_CREATE_LBPREFIX), responder_(&ctx_) {
		service_->RequestCreateLoadBalancerPrefix(&ctx_, &request_, &responder_, cq_, cq_,
														   this);
	}
	int Proceed() override;
};

class CheckVniInUseCall final : BaseCall {
	ServerContext ctx_;
	CheckVniInUseRequest request_;
	CheckVniInUseResponse reply_;
	ServerAsyncResponseWriter<CheckVniInUseResponse> responder_;

public:
	CheckVniInUseCall(DPDKonmetal::AsyncService* service, ServerCompletionQueue* cq)
	: BaseCall(service, cq, DP_REQ_TYPE_CHECK_VNIINUSE), responder_(&ctx_) {
		service_->RequestCheckVniInUse(&ctx_, &request_, &responder_, cq_, cq_,
														   this);
	}
	int Proceed() override;
};

class ResetVniCall final : BaseCall {
	ServerContext ctx_;
	ResetVniRequest request_;
	ResetVniResponse reply_;
	ServerAsyncResponseWriter<ResetVniResponse> responder_;

public:
	ResetVniCall(DPDKonmetal::AsyncService* service, ServerCompletionQueue* cq)
	: BaseCall(service, cq, DP_REQ_TYPE_RESET_VNI), responder_(&ctx_) {
		service_->RequestResetVni(&ctx_, &request_, &responder_, cq_, cq_,
														   this);
	}
	int Proceed() override;
};

class DeleteLoadBalancerPrefixCall final : BaseCall {
	ServerContext ctx_;
	DeleteLoadBalancerPrefixRequest request_;
	DeleteLoadBalancerPrefixResponse reply_;
	ServerAsyncResponseWriter<DeleteLoadBalancerPrefixResponse> responder_;

public:
	DeleteLoadBalancerPrefixCall(DPDKonmetal::AsyncService* service, ServerCompletionQueue* cq)
	: BaseCall(service, cq, DP_REQ_TYPE_DELETE_LBPREFIX), responder_(&ctx_) {
		service_->RequestDeleteLoadBalancerPrefix(&ctx_, &request_, &responder_, cq_, cq_,
														   this);
	}
	int Proceed() override;
};

class ListLoadBalancerPrefixesCall final : BaseCall {
	ServerContext ctx_;
	ListLoadBalancerPrefixesRequest request_;
	ListLoadBalancerPrefixesResponse reply_;
	ServerAsyncResponseWriter<ListLoadBalancerPrefixesResponse> responder_;
private:
	static void ListCallback(struct dpgrpc_reply *reply, void *context);
public:
	ListLoadBalancerPrefixesCall(DPDKonmetal::AsyncService* service, ServerCompletionQueue* cq)
	: BaseCall(service, cq, DP_REQ_TYPE_LIST_LBPREFIXES), responder_(&ctx_) {
		service_->RequestListLoadBalancerPrefixes(&ctx_, &request_, &responder_, cq_, cq_,
														   this);
	}
	int Proceed() override;
};

class CreatePrefixCall final : BaseCall {
	ServerContext ctx_;
	CreatePrefixRequest request_;
	CreatePrefixResponse reply_;
	ServerAsyncResponseWriter<CreatePrefixResponse> responder_;

public:
	CreatePrefixCall(DPDKonmetal::AsyncService* service, ServerCompletionQueue* cq)
	: BaseCall(service, cq, DP_REQ_TYPE_CREATE_PREFIX), responder_(&ctx_) {
		service_->RequestCreatePrefix(&ctx_, &request_, &responder_, cq_, cq_,
										 this);
	}
	int Proceed() override;
};

class DeletePrefixCall final : BaseCall {
	ServerContext ctx_;
	DeletePrefixRequest request_;
	DeletePrefixResponse reply_;
	ServerAsyncResponseWriter<DeletePrefixResponse> responder_;

public:
	DeletePrefixCall(DPDKonmetal::AsyncService* service, ServerCompletionQueue* cq)
	: BaseCall(service, cq, DP_REQ_TYPE_DELETE_PREFIX), responder_(&ctx_) {
		service_->RequestDeletePrefix(&ctx_, &request_, &responder_, cq_, cq_,
										 this);
	}
	int Proceed() override;
};

class ListPrefixesCall final : BaseCall {
	ServerContext ctx_;
	ListPrefixesRequest request_;
	ListPrefixesResponse reply_;
	ServerAsyncResponseWriter<ListPrefixesResponse> responder_;
private:
	static void ListCallback(struct dpgrpc_reply *reply, void *context);
public:
	ListPrefixesCall(DPDKonmetal::AsyncService* service, ServerCompletionQueue* cq)
	: BaseCall(service, cq, DP_REQ_TYPE_LIST_PREFIXES), responder_(&ctx_) {
		service_->RequestListPrefixes(&ctx_, &request_, &responder_, cq_, cq_,
										 this);
	}
	int Proceed() override;
};

class CreateVIPCall final : BaseCall {
	ServerContext ctx_;
	CreateVIPRequest request_;
	CreateVIPResponse reply_;
	ServerAsyncResponseWriter<CreateVIPResponse> responder_;

public:
	CreateVIPCall(DPDKonmetal::AsyncService* service, ServerCompletionQueue* cq)
	: BaseCall(service, cq, DP_REQ_TYPE_CREATE_VIP), responder_(&ctx_) {
		service_->RequestCreateVIP(&ctx_, &request_, &responder_, cq_, cq_,
										 this);
	}
	int Proceed() override;
};

class CreateLoadBalancerCall final : BaseCall {
	ServerContext ctx_;
	CreateLoadBalancerRequest request_;
	CreateLoadBalancerResponse reply_;
	ServerAsyncResponseWriter<CreateLoadBalancerResponse> responder_;

public:
	CreateLoadBalancerCall(DPDKonmetal::AsyncService* service, ServerCompletionQueue* cq)
	: BaseCall(service, cq, DP_REQ_TYPE_CREATE_LB), responder_(&ctx_) {
		service_->RequestCreateLoadBalancer(&ctx_, &request_, &responder_, cq_, cq_,
											this);
	}
	int Proceed() override;
};

class GetLoadBalancerCall final : BaseCall {
	ServerContext ctx_;
	GetLoadBalancerRequest request_;
	GetLoadBalancerResponse reply_;
	ServerAsyncResponseWriter<GetLoadBalancerResponse> responder_;

public:
	GetLoadBalancerCall(DPDKonmetal::AsyncService* service, ServerCompletionQueue* cq)
	: BaseCall(service, cq, DP_REQ_TYPE_GET_LB), responder_(&ctx_) {
		service_->RequestGetLoadBalancer(&ctx_, &request_, &responder_, cq_, cq_,
											this);
	}
	int Proceed() override;
};

class DeleteLoadBalancerCall final : BaseCall {
	ServerContext ctx_;
	DeleteLoadBalancerRequest request_;
	DeleteLoadBalancerResponse reply_;
	ServerAsyncResponseWriter<DeleteLoadBalancerResponse> responder_;

public:
	DeleteLoadBalancerCall(DPDKonmetal::AsyncService* service, ServerCompletionQueue* cq)
	: BaseCall(service, cq, DP_REQ_TYPE_DELETE_LB), responder_(&ctx_) {
		service_->RequestDeleteLoadBalancer(&ctx_, &request_, &responder_, cq_, cq_,
											this);
	}
	int Proceed() override;
};

class CreateLoadBalancerTargetCall final : BaseCall {
	ServerContext ctx_;
	CreateLoadBalancerTargetRequest request_;
	CreateLoadBalancerTargetResponse reply_;
	ServerAsyncResponseWriter<CreateLoadBalancerTargetResponse> responder_;

public:
	CreateLoadBalancerTargetCall(DPDKonmetal::AsyncService* service, ServerCompletionQueue* cq)
	: BaseCall(service, cq, DP_REQ_TYPE_CREATE_LBTARGET), responder_(&ctx_) {
		service_->RequestCreateLoadBalancerTarget(&ctx_, &request_, &responder_, cq_, cq_,
											   this);
	}
	int Proceed() override;
};

class DeleteLoadBalancerTargetCall final : BaseCall {
	ServerContext ctx_;
	DeleteLoadBalancerTargetRequest request_;
	DeleteLoadBalancerTargetResponse reply_;
	ServerAsyncResponseWriter<DeleteLoadBalancerTargetResponse> responder_;

public:
	DeleteLoadBalancerTargetCall(DPDKonmetal::AsyncService* service, ServerCompletionQueue* cq)
	: BaseCall(service, cq, DP_REQ_TYPE_DELETE_LBTARGET), responder_(&ctx_) {
		service_->RequestDeleteLoadBalancerTarget(&ctx_, &request_, &responder_, cq_, cq_,
												  this);
	}
	int Proceed() override;
};

class ListLoadBalancerTargetsCall final : BaseCall {
	ServerContext ctx_;
	ListLoadBalancerTargetsRequest request_;
	ListLoadBalancerTargetsResponse reply_;
	ServerAsyncResponseWriter<ListLoadBalancerTargetsResponse> responder_;
private:
	static void ListCallback(struct dpgrpc_reply *reply, void *context);
public:
	ListLoadBalancerTargetsCall(DPDKonmetal::AsyncService* service, ServerCompletionQueue* cq)
	: BaseCall(service, cq, DP_REQ_TYPE_LIST_LBTARGETS), responder_(&ctx_) {
		service_->RequestListLoadBalancerTargets(&ctx_, &request_, &responder_, cq_, cq_,
												this);
	}
	int Proceed() override;
};

class DeleteVIPCall final : BaseCall {
	ServerContext ctx_;
	DeleteVIPRequest request_;
	DeleteVIPResponse reply_;
	ServerAsyncResponseWriter<DeleteVIPResponse> responder_;

public:
	DeleteVIPCall(DPDKonmetal::AsyncService* service, ServerCompletionQueue* cq)
	: BaseCall(service, cq, DP_REQ_TYPE_DELETE_VIP), responder_(&ctx_) {
		service_->RequestDeleteVIP(&ctx_, &request_, &responder_, cq_, cq_,
										 this);
	}
	int Proceed() override;
};

class GetVIPCall final : BaseCall {
	ServerContext ctx_;
	GetVIPRequest request_;
	GetVIPResponse reply_;
	ServerAsyncResponseWriter<GetVIPResponse> responder_;

public:
	GetVIPCall(DPDKonmetal::AsyncService* service, ServerCompletionQueue* cq)
	: BaseCall(service, cq, DP_REQ_TYPE_GET_VIP), responder_(&ctx_) {
		service_->RequestGetVIP(&ctx_, &request_, &responder_, cq_, cq_,
										 this);
	}
	int Proceed() override;
};

class CreateInterfaceCall final : BaseCall {
	ServerContext ctx_;
	CreateInterfaceRequest request_;
	CreateInterfaceResponse reply_;
	ServerAsyncResponseWriter<CreateInterfaceResponse> responder_;

public:
	CreateInterfaceCall(DPDKonmetal::AsyncService* service, ServerCompletionQueue* cq)
	: BaseCall(service, cq, DP_REQ_TYPE_CREATE_INTERFACE), responder_(&ctx_) {
		service_->RequestCreateInterface(&ctx_, &request_, &responder_, cq_, cq_,
										 this);
	}
	int Proceed() override;
};

class DeleteInterfaceCall final : BaseCall {
	ServerContext ctx_;
	DeleteInterfaceRequest request_;
	DeleteInterfaceResponse reply_;
	ServerAsyncResponseWriter<DeleteInterfaceResponse> responder_;

public:
	DeleteInterfaceCall(DPDKonmetal::AsyncService* service, ServerCompletionQueue* cq)
	: BaseCall(service, cq, DP_REQ_TYPE_DELETE_INTERFACE), responder_(&ctx_) {
		service_->RequestDeleteInterface(&ctx_, &request_, &responder_, cq_, cq_,
										 this);
	}
	int Proceed() override;
};

class CreateRouteCall final : BaseCall {
	ServerContext ctx_;
	CreateRouteRequest request_;
	CreateRouteResponse reply_;
	ServerAsyncResponseWriter<CreateRouteResponse> responder_;

public:
	CreateRouteCall(DPDKonmetal::AsyncService* service, ServerCompletionQueue* cq)
	: BaseCall(service, cq, DP_REQ_TYPE_CREATE_ROUTE), responder_(&ctx_) {
		service_->RequestCreateRoute(&ctx_, &request_, &responder_, cq_, cq_,
										 this);
	}
	int Proceed() override;
};

class DeleteRouteCall final : BaseCall {
	ServerContext ctx_;
	DeleteRouteRequest request_;
	DeleteRouteResponse reply_;
	ServerAsyncResponseWriter<DeleteRouteResponse> responder_;

public:
	DeleteRouteCall(DPDKonmetal::AsyncService* service, ServerCompletionQueue* cq)
	: BaseCall(service, cq, DP_REQ_TYPE_DELETE_ROUTE), responder_(&ctx_) {
		service_->RequestDeleteRoute(&ctx_, &request_, &responder_, cq_, cq_,
										 this);
	}
	int Proceed() override;
};

class GetInterfaceCall final : BaseCall {
	ServerContext ctx_;
	GetInterfaceRequest request_;
	GetInterfaceResponse reply_;
	ServerAsyncResponseWriter<GetInterfaceResponse> responder_;

public:
	GetInterfaceCall(DPDKonmetal::AsyncService* service, ServerCompletionQueue* cq)
	: BaseCall(service, cq, DP_REQ_TYPE_GET_INTERFACE), responder_(&ctx_) {
		service_->RequestGetInterface(&ctx_, &request_, &responder_, cq_, cq_,
										 this);
	}
	int Proceed() override;
};

class ListRoutesCall final : BaseCall {
	ServerContext ctx_;
	ListRoutesRequest request_;
	ListRoutesResponse reply_;
	ServerAsyncResponseWriter<ListRoutesResponse> responder_;
private:
	static void ListCallback(struct dpgrpc_reply *reply, void *context);
public:
	ListRoutesCall(DPDKonmetal::AsyncService* service, ServerCompletionQueue* cq)
	: BaseCall(service, cq, DP_REQ_TYPE_LIST_ROUTES), responder_(&ctx_) {
		service_->RequestListRoutes(&ctx_, &request_, &responder_, cq_, cq_,
										 this);
	}
	int Proceed() override;
};

class ListInterfacesCall final : BaseCall {
	ServerContext ctx_;
	ListInterfacesRequest request_;
	ListInterfacesResponse reply_;
	ServerAsyncResponseWriter<ListInterfacesResponse> responder_;
private:
	static void ListCallback(struct dpgrpc_reply *reply, void *context);
public:
	ListInterfacesCall(DPDKonmetal::AsyncService* service, ServerCompletionQueue* cq)
	: BaseCall(service, cq, DP_REQ_TYPE_LIST_INTERFACES), responder_(&ctx_) {
		service_->RequestListInterfaces(&ctx_, &request_, &responder_, cq_, cq_,
										 this);
	}
	int Proceed() override;
};

class CreateNATCall final: BaseCall {
	ServerContext ctx_;
	CreateNATRequest request_;
	CreateNATResponse reply_;
	ServerAsyncResponseWriter<CreateNATResponse> responder_;

public:
	CreateNATCall(DPDKonmetal::AsyncService* service, ServerCompletionQueue* cq)
	: BaseCall(service, cq, DP_REQ_TYPE_CREATE_NAT), responder_(&ctx_) {
		service_->RequestCreateNAT(&ctx_, &request_, &responder_, cq_, cq_,
										 this);
	}
	int	Proceed() override;
};

class ListLocalNATsCall final: BaseCall {
	ServerContext ctx_;
	ListLocalNATsRequest request_;
	ListLocalNATsResponse reply_;
	ServerAsyncResponseWriter<ListLocalNATsResponse> responder_;
private:
	static void ListCallback(struct dpgrpc_reply *reply, void *context);
public:
	ListLocalNATsCall(DPDKonmetal::AsyncService* service, ServerCompletionQueue* cq)
	: BaseCall(service, cq, DP_REQ_TYPE_LIST_LOCALNATS), responder_(&ctx_) {
		service_->RequestListLocalNATs(&ctx_, &request_, &responder_, cq_, cq_,
										 this);
	}
	int	Proceed() override;
};

class ListNeighborNATsCall final: BaseCall {
	ServerContext ctx_;
	ListNeighborNATsRequest request_;
	ListNeighborNATsResponse reply_;
	ServerAsyncResponseWriter<ListNeighborNATsResponse> responder_;
private:
	static void ListCallback(struct dpgrpc_reply *reply, void *context);
public:
	ListNeighborNATsCall(DPDKonmetal::AsyncService* service, ServerCompletionQueue* cq)
	: BaseCall(service, cq, DP_REQ_TYPE_LIST_NEIGHNATS), responder_(&ctx_) {
		service_->RequestListNeighborNATs(&ctx_, &request_, &responder_, cq_, cq_,
										 this);
	}
	int	Proceed() override;
};

class GetNATCall final: BaseCall {
	ServerContext ctx_;
	GetNATRequest request_;
	GetNATResponse reply_;
	ServerAsyncResponseWriter<GetNATResponse> responder_;

public:
	GetNATCall(DPDKonmetal::AsyncService* service, ServerCompletionQueue* cq)
	: BaseCall(service, cq, DP_REQ_TYPE_GET_NAT), responder_(&ctx_) {
		service_->RequestGetNAT(&ctx_, &request_, &responder_, cq_, cq_,
								this);
	}
	int	Proceed() override;
};

class DeleteNATCall final: BaseCall {
	ServerContext ctx_;
	DeleteNATRequest request_;
	DeleteNATResponse reply_;
	ServerAsyncResponseWriter<DeleteNATResponse> responder_;

public:
	DeleteNATCall(DPDKonmetal::AsyncService* service, ServerCompletionQueue* cq)
	: BaseCall(service, cq, DP_REQ_TYPE_DELETE_NAT), responder_(&ctx_) {
		service_->RequestDeleteNAT(&ctx_, &request_, &responder_, cq_, cq_,
										 this);
	}
	int	Proceed() override;
};

class CreateNeighborNATCall final: BaseCall {
	ServerContext ctx_;
	CreateNeighborNATRequest request_;
	CreateNeighborNATResponse reply_;
	ServerAsyncResponseWriter<CreateNeighborNATResponse> responder_;

public:
	CreateNeighborNATCall(DPDKonmetal::AsyncService* service, ServerCompletionQueue* cq)
	: BaseCall(service, cq, DP_REQ_TYPE_CREATE_NEIGHNAT), responder_(&ctx_) {
		service_->RequestCreateNeighborNAT(&ctx_, &request_, &responder_, cq_, cq_,
										 this);
	}
	int	Proceed() override;
};

class DeleteNeighborNATCall final: BaseCall {
	ServerContext ctx_;
	DeleteNeighborNATRequest request_;
	DeleteNeighborNATResponse reply_;
	ServerAsyncResponseWriter<DeleteNeighborNATResponse> responder_;

public:
	DeleteNeighborNATCall(DPDKonmetal::AsyncService* service, ServerCompletionQueue* cq)
	: BaseCall(service, cq, DP_REQ_TYPE_DELETE_NEIGHNAT), responder_(&ctx_) {
		service_->RequestDeleteNeighborNAT(&ctx_, &request_, &responder_, cq_, cq_,
										 this);
	}
	int	Proceed() override;
};

class CheckInitializedCall final : BaseCall {
	ServerContext ctx_;
	CheckInitializedRequest request_;
	CheckInitializedResponse reply_;
	ServerAsyncResponseWriter<CheckInitializedResponse> responder_;

public:
	CheckInitializedCall(DPDKonmetal::AsyncService* service, ServerCompletionQueue* cq)
	: BaseCall(service, cq, DP_REQ_TYPE_CHECK_INITIALIZED), responder_(&ctx_) {
		service_->RequestCheckInitialized(&ctx_, &request_, &responder_, cq_, cq_,
										 this);
	}
	int Proceed() override;
};

class InitializeCall final : BaseCall {
	ServerContext ctx_;
	InitializeRequest request_;
	InitializeResponse reply_;
	ServerAsyncResponseWriter<InitializeResponse> responder_;

public:
	InitializeCall(DPDKonmetal::AsyncService* service, ServerCompletionQueue* cq)
	: BaseCall(service, cq, DP_REQ_TYPE_INITIALIZE), responder_(&ctx_) {
		service_->RequestInitialize(&ctx_, &request_, &responder_, cq_, cq_,
										 this);
	}
	int Proceed() override;
};

class CreateFirewallRuleCall final : BaseCall {
	ServerContext ctx_;
	CreateFirewallRuleRequest request_;
	CreateFirewallRuleResponse reply_;
	ServerAsyncResponseWriter<CreateFirewallRuleResponse> responder_;

public:
	CreateFirewallRuleCall(DPDKonmetal::AsyncService* service, ServerCompletionQueue* cq)
	: BaseCall(service, cq, DP_REQ_TYPE_CREATE_FWRULE), responder_(&ctx_) {
		service_->RequestCreateFirewallRule(&ctx_, &request_, &responder_, cq_, cq_,
										 this);
	}
	int Proceed() override;
};

class DeleteFirewallRuleCall final : BaseCall {
	ServerContext ctx_;
	DeleteFirewallRuleRequest request_;
	DeleteFirewallRuleResponse reply_;
	ServerAsyncResponseWriter<DeleteFirewallRuleResponse> responder_;

public:
	DeleteFirewallRuleCall(DPDKonmetal::AsyncService* service, ServerCompletionQueue* cq)
	: BaseCall(service, cq, DP_REQ_TYPE_DELETE_FWRULE), responder_(&ctx_) {
		service_->RequestDeleteFirewallRule(&ctx_, &request_, &responder_, cq_, cq_,
											this);
	}
	int Proceed() override;
};

class GetFirewallRuleCall final : BaseCall {
	ServerContext ctx_;
	GetFirewallRuleRequest request_;
	GetFirewallRuleResponse reply_;
	ServerAsyncResponseWriter<GetFirewallRuleResponse> responder_;

public:
	GetFirewallRuleCall(DPDKonmetal::AsyncService* service, ServerCompletionQueue* cq)
	: BaseCall(service, cq, DP_REQ_TYPE_GET_FWRULE), responder_(&ctx_) {
		service_->RequestGetFirewallRule(&ctx_, &request_, &responder_, cq_, cq_,
										 this);
	}
	int Proceed() override;
};

class ListFirewallRulesCall final : BaseCall {
	ServerContext ctx_;
	ListFirewallRulesRequest request_;
	ListFirewallRulesResponse reply_;
	ServerAsyncResponseWriter<ListFirewallRulesResponse> responder_;
private:
	static void ListCallback(struct dpgrpc_reply *reply, void *context);
public:
	ListFirewallRulesCall(DPDKonmetal::AsyncService* service, ServerCompletionQueue* cq)
	: BaseCall(service, cq, DP_REQ_TYPE_LIST_FWRULES), responder_(&ctx_) {
		service_->RequestListFirewallRules(&ctx_, &request_, &responder_, cq_, cq_,
										 this);
	}
	int Proceed() override;
};

class GetVersionCall final : BaseCall {
	ServerContext ctx_;
	GetVersionRequest request_;
	GetVersionResponse reply_;
	ServerAsyncResponseWriter<GetVersionResponse> responder_;

public:
	GetVersionCall(DPDKonmetal::AsyncService* service, ServerCompletionQueue* cq)
	: BaseCall(service, cq, DP_REQ_TYPE_GET_VERSION), responder_(&ctx_) {
		service_->RequestGetVersion(&ctx_, &request_, &responder_, cq_, cq_,
									this);
	}
	int Proceed() override;
};

#endif //__INCLUDE_DP_ASYNC_GRPC_H__
