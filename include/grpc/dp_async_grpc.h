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
	static void SetErrStatus(Status *status, dpgrpc_reply *reply);
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

class CreateLBTargetPfxCall final : BaseCall {
	ServerContext ctx_;
	CreateInterfaceLoadBalancerPrefixRequest request_;
	CreateInterfaceLoadBalancerPrefixResponse reply_;
	ServerAsyncResponseWriter<CreateInterfaceLoadBalancerPrefixResponse> responder_;

public:
	CreateLBTargetPfxCall(DPDKonmetal::AsyncService* service, ServerCompletionQueue* cq)
	: BaseCall(service, cq, DP_REQ_TYPE_ADD_LBPREFIX), responder_(&ctx_) {
		service_->RequestCreateInterfaceLoadBalancerPrefix(&ctx_, &request_, &responder_, cq_, cq_,
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
	: BaseCall(service, cq, DP_REQ_TYPE_VNI_INUSE), responder_(&ctx_) {
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
	: BaseCall(service, cq, DP_REQ_TYPE_VNI_RESET), responder_(&ctx_) {
		service_->RequestResetVni(&ctx_, &request_, &responder_, cq_, cq_,
														   this);
	}
	int Proceed() override;
};

class DelLBTargetPfxCall final : BaseCall {
	ServerContext ctx_;
	DeleteInterfaceLoadBalancerPrefixRequest request_;
	DeleteInterfaceLoadBalancerPrefixResponse reply_;
	ServerAsyncResponseWriter<DeleteInterfaceLoadBalancerPrefixResponse> responder_;

public:
	DelLBTargetPfxCall(DPDKonmetal::AsyncService* service, ServerCompletionQueue* cq)
	: BaseCall(service, cq, DP_REQ_TYPE_DEL_LBPREFIX), responder_(&ctx_) {
		service_->RequestDeleteInterfaceLoadBalancerPrefix(&ctx_, &request_, &responder_, cq_, cq_,
														   this);
	}
	int Proceed() override;
};

class ListLBTargetPfxCall final : BaseCall {
	ServerContext ctx_;
	ListInterfaceLoadBalancerPrefixesRequest request_;
	ListInterfaceLoadBalancerPrefixesResponse reply_;
	ServerAsyncResponseWriter<ListInterfaceLoadBalancerPrefixesResponse> responder_;
private:
	static void ListCallback(struct dpgrpc_reply *reply, void *context);
public:
	ListLBTargetPfxCall(DPDKonmetal::AsyncService* service, ServerCompletionQueue* cq)
	: BaseCall(service, cq, DP_REQ_TYPE_LIST_LBPREFIXES), responder_(&ctx_) {
		service_->RequestListInterfaceLoadBalancerPrefixes(&ctx_, &request_, &responder_, cq_, cq_,
														   this);
	}
	int Proceed() override;
};

class CreatePfxCall final : BaseCall {
	ServerContext ctx_;
	CreateInterfacePrefixRequest request_;
	CreateInterfacePrefixResponse reply_;
	ServerAsyncResponseWriter<CreateInterfacePrefixResponse> responder_;

public:
	CreatePfxCall(DPDKonmetal::AsyncService* service, ServerCompletionQueue* cq)
	: BaseCall(service, cq, DP_REQ_TYPE_ADD_PREFIX), responder_(&ctx_) {
		service_->RequestCreateInterfacePrefix(&ctx_, &request_, &responder_, cq_, cq_,
										 this);
	}
	int Proceed() override;
};

class DelPfxCall final : BaseCall {
	ServerContext ctx_;
	DeleteInterfacePrefixRequest request_;
	DeleteInterfacePrefixResponse reply_;
	ServerAsyncResponseWriter<DeleteInterfacePrefixResponse> responder_;

public:
	DelPfxCall(DPDKonmetal::AsyncService* service, ServerCompletionQueue* cq)
	: BaseCall(service, cq, DP_REQ_TYPE_DEL_PREFIX), responder_(&ctx_) {
		service_->RequestDeleteInterfacePrefix(&ctx_, &request_, &responder_, cq_, cq_,
										 this);
	}
	int Proceed() override;
};

class ListPfxCall final : BaseCall {
	ServerContext ctx_;
	ListInterfacePrefixesRequest request_;
	ListInterfacePrefixesResponse reply_;
	ServerAsyncResponseWriter<ListInterfacePrefixesResponse> responder_;
private:
	static void ListCallback(struct dpgrpc_reply *reply, void *context);
public:
	ListPfxCall(DPDKonmetal::AsyncService* service, ServerCompletionQueue* cq)
	: BaseCall(service, cq, DP_REQ_TYPE_LIST_PREFIXES), responder_(&ctx_) {
		service_->RequestListInterfacePrefixes(&ctx_, &request_, &responder_, cq_, cq_,
										 this);
	}
	int Proceed() override;
};

class CreateVIPCall final : BaseCall {
	ServerContext ctx_;
	CreateInterfaceVIPRequest request_;
	CreateInterfaceVIPResponse reply_;
	ServerAsyncResponseWriter<CreateInterfaceVIPResponse> responder_;

public:
	CreateVIPCall(DPDKonmetal::AsyncService* service, ServerCompletionQueue* cq)
	: BaseCall(service, cq, DP_REQ_TYPE_ADD_VIP), responder_(&ctx_) {
		service_->RequestCreateInterfaceVIP(&ctx_, &request_, &responder_, cq_, cq_,
										 this);
	}
	int Proceed() override;
};

class CreateLBCall final : BaseCall {
	ServerContext ctx_;
	CreateLoadBalancerRequest request_;
	CreateLoadBalancerResponse reply_;
	ServerAsyncResponseWriter<CreateLoadBalancerResponse> responder_;

public:
	CreateLBCall(DPDKonmetal::AsyncService* service, ServerCompletionQueue* cq)
	: BaseCall(service, cq, DP_REQ_TYPE_ADD_LB), responder_(&ctx_) {
		service_->RequestCreateLoadBalancer(&ctx_, &request_, &responder_, cq_, cq_,
											this);
	}
	int Proceed() override;
};

class GetLBCall final : BaseCall {
	ServerContext ctx_;
	GetLoadBalancerRequest request_;
	GetLoadBalancerResponse reply_;
	ServerAsyncResponseWriter<GetLoadBalancerResponse> responder_;

public:
	GetLBCall(DPDKonmetal::AsyncService* service, ServerCompletionQueue* cq)
	: BaseCall(service, cq, DP_REQ_TYPE_GET_LB), responder_(&ctx_) {
		service_->RequestGetLoadBalancer(&ctx_, &request_, &responder_, cq_, cq_,
											this);
	}
	int Proceed() override;
};

class DelLBCall final : BaseCall {
	ServerContext ctx_;
	DeleteLoadBalancerRequest request_;
	DeleteLoadBalancerResponse reply_;
	ServerAsyncResponseWriter<DeleteLoadBalancerResponse> responder_;

public:
	DelLBCall(DPDKonmetal::AsyncService* service, ServerCompletionQueue* cq)
	: BaseCall(service, cq, DP_REQ_TYPE_DEL_LB), responder_(&ctx_) {
		service_->RequestDeleteLoadBalancer(&ctx_, &request_, &responder_, cq_, cq_,
											this);
	}
	int Proceed() override;
};

class CreateLBVIPCall final : BaseCall {
	ServerContext ctx_;
	CreateLoadBalancerTargetRequest request_;
	CreateLoadBalancerTargetResponse reply_;
	ServerAsyncResponseWriter<CreateLoadBalancerTargetResponse> responder_;

public:
	CreateLBVIPCall(DPDKonmetal::AsyncService* service, ServerCompletionQueue* cq)
	: BaseCall(service, cq, DP_REQ_TYPE_ADD_LBTARGET), responder_(&ctx_) {
		service_->RequestCreateLoadBalancerTarget(&ctx_, &request_, &responder_, cq_, cq_,
											   this);
	}
	int Proceed() override;
};

class DelLBVIPCall final : BaseCall {
	ServerContext ctx_;
	DeleteLoadBalancerTargetRequest request_;
	DeleteLoadBalancerTargetResponse reply_;
	ServerAsyncResponseWriter<DeleteLoadBalancerTargetResponse> responder_;

public:
	DelLBVIPCall(DPDKonmetal::AsyncService* service, ServerCompletionQueue* cq)
	: BaseCall(service, cq, DP_REQ_TYPE_DEL_LBTARGET), responder_(&ctx_) {
		service_->RequestDeleteLoadBalancerTarget(&ctx_, &request_, &responder_, cq_, cq_,
												  this);
	}
	int Proceed() override;
};

class GetLBVIPBackendsCall final : BaseCall {
	ServerContext ctx_;
	ListLoadBalancerTargetsRequest request_;
	ListLoadBalancerTargetsResponse reply_;
	ServerAsyncResponseWriter<ListLoadBalancerTargetsResponse> responder_;
private:
	static void ListCallback(struct dpgrpc_reply *reply, void *context);
public:
	GetLBVIPBackendsCall(DPDKonmetal::AsyncService* service, ServerCompletionQueue* cq)
	: BaseCall(service, cq, DP_REQ_TYPE_LIST_LBTARGETS), responder_(&ctx_) {
		service_->RequestListLoadBalancerTargets(&ctx_, &request_, &responder_, cq_, cq_,
												this);
	}
	int Proceed() override;
};

class DelVIPCall final : BaseCall {
	ServerContext ctx_;
	DeleteInterfaceVIPRequest request_;
	DeleteInterfaceVIPResponse reply_;
	ServerAsyncResponseWriter<DeleteInterfaceVIPResponse> responder_;

public:
	DelVIPCall(DPDKonmetal::AsyncService* service, ServerCompletionQueue* cq)
	: BaseCall(service, cq, DP_REQ_TYPE_DEL_VIP), responder_(&ctx_) {
		service_->RequestDeleteInterfaceVIP(&ctx_, &request_, &responder_, cq_, cq_,
										 this);
	}
	int Proceed() override;
};

class GetVIPCall final : BaseCall {
	ServerContext ctx_;
	GetInterfaceVIPRequest request_;
	GetInterfaceVIPResponse reply_;
	ServerAsyncResponseWriter<GetInterfaceVIPResponse> responder_;

public:
	GetVIPCall(DPDKonmetal::AsyncService* service, ServerCompletionQueue* cq)
	: BaseCall(service, cq, DP_REQ_TYPE_GET_VIP), responder_(&ctx_) {
		service_->RequestGetInterfaceVIP(&ctx_, &request_, &responder_, cq_, cq_,
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
	: BaseCall(service, cq, DP_REQ_TYPE_ADD_INTERFACE), responder_(&ctx_) {
		service_->RequestCreateInterface(&ctx_, &request_, &responder_, cq_, cq_,
										 this);
	}
	int Proceed() override;
};

class DelInterfaceCall final : BaseCall {
	ServerContext ctx_;
	DeleteInterfaceRequest request_;
	DeleteInterfaceResponse reply_;
	ServerAsyncResponseWriter<DeleteInterfaceResponse> responder_;

public:
	DelInterfaceCall(DPDKonmetal::AsyncService* service, ServerCompletionQueue* cq)
	: BaseCall(service, cq, DP_REQ_TYPE_DEL_INTERFACE), responder_(&ctx_) {
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
	: BaseCall(service, cq, DP_REQ_TYPE_ADD_ROUTE), responder_(&ctx_) {
		service_->RequestCreateRoute(&ctx_, &request_, &responder_, cq_, cq_,
										 this);
	}
	int Proceed() override;
};

class DelRouteCall final : BaseCall {
	ServerContext ctx_;
	DeleteRouteRequest request_;
	DeleteRouteResponse reply_;
	ServerAsyncResponseWriter<DeleteRouteResponse> responder_;

public:
	DelRouteCall(DPDKonmetal::AsyncService* service, ServerCompletionQueue* cq)
	: BaseCall(service, cq, DP_REQ_TYPE_DEL_ROUTE), responder_(&ctx_) {
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

class CreateNATVIPCall final: BaseCall {
	ServerContext ctx_;
	CreateNATRequest request_;
	CreateNATResponse reply_;
	ServerAsyncResponseWriter<CreateNATResponse> responder_;

public:
	CreateNATVIPCall(DPDKonmetal::AsyncService* service, ServerCompletionQueue* cq)
	: BaseCall(service, cq, DP_REQ_TYPE_ADD_NAT), responder_(&ctx_) {
		service_->RequestCreateNAT(&ctx_, &request_, &responder_, cq_, cq_,
										 this);
	}
	int	Proceed() override;
};

class GetNATInfoCall final: BaseCall {
	ServerContext ctx_;
	GetNATInfoRequest request_;
	GetNATInfoResponse reply_;
	ServerAsyncResponseWriter<GetNATInfoResponse> responder_;
private:
	static void ListCallbackLocal(struct dpgrpc_reply *reply, void *context);
	static void ListCallbackNeigh(struct dpgrpc_reply *reply, void *context);
public:
	GetNATInfoCall(DPDKonmetal::AsyncService* service, ServerCompletionQueue* cq)
	: BaseCall(service, cq, DP_REQ_TYPE_GET_NATINFO), responder_(&ctx_) {
		service_->RequestGetNATInfo(&ctx_, &request_, &responder_, cq_, cq_,
										 this);
	}
	int	Proceed() override;
};

class GetNATVIPCall final: BaseCall {
	ServerContext ctx_;
	GetNATRequest request_;
	GetNATResponse reply_;
	ServerAsyncResponseWriter<GetNATResponse> responder_;

public:
	GetNATVIPCall(DPDKonmetal::AsyncService* service, ServerCompletionQueue* cq)
	: BaseCall(service, cq, DP_REQ_TYPE_GET_NAT), responder_(&ctx_) {
		service_->RequestGetNAT(&ctx_, &request_, &responder_, cq_, cq_,
								this);
	}
	int	Proceed() override;
};

class DeleteNATVIPCall final: BaseCall {
	ServerContext ctx_;
	DeleteNATRequest request_;
	DeleteNATResponse reply_;
	ServerAsyncResponseWriter<DeleteNATResponse> responder_;

public:
	DeleteNATVIPCall(DPDKonmetal::AsyncService* service, ServerCompletionQueue* cq)
	: BaseCall(service, cq, DP_REQ_TYPE_DEL_NAT), responder_(&ctx_) {
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
	: BaseCall(service, cq, DP_REQ_TYPE_ADD_NEIGHNAT), responder_(&ctx_) {
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
	: BaseCall(service, cq, DP_REQ_TYPE_DEL_NEIGHNAT), responder_(&ctx_) {
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
	: BaseCall(service, cq, DP_REQ_TYPE_INITIALIZED), responder_(&ctx_) {
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
	: BaseCall(service, cq, DP_REQ_TYPE_INIT), responder_(&ctx_) {
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
	: BaseCall(service, cq, DP_REQ_TYPE_ADD_FWRULE), responder_(&ctx_) {
		service_->RequestCreateFirewallRule(&ctx_, &request_, &responder_, cq_, cq_,
										 this);
	}
	int Proceed() override;
};

class DelFirewallRuleCall final : BaseCall {
	ServerContext ctx_;
	DeleteFirewallRuleRequest request_;
	DeleteFirewallRuleResponse reply_;
	ServerAsyncResponseWriter<DeleteFirewallRuleResponse> responder_;

public:
	DelFirewallRuleCall(DPDKonmetal::AsyncService* service, ServerCompletionQueue* cq)
	: BaseCall(service, cq, DP_REQ_TYPE_DEL_FWRULE), responder_(&ctx_) {
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
