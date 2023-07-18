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
		service_->RequestcreateInterfaceLoadBalancerPrefix(&ctx_, &request_, &responder_, cq_, cq_,
														   this);
	}
	int Proceed() override;
};

class IsVniInUseCall final : BaseCall {
	ServerContext ctx_;
	IsVniInUseRequest request_;
	IsVniInUseResponse reply_;
	ServerAsyncResponseWriter<IsVniInUseResponse> responder_;

public:
	IsVniInUseCall(DPDKonmetal::AsyncService* service, ServerCompletionQueue* cq)
	: BaseCall(service, cq, DP_REQ_TYPE_VNI_INUSE), responder_(&ctx_) {
		service_->RequestisVniInUse(&ctx_, &request_, &responder_, cq_, cq_,
														   this);
	}
	int Proceed() override;
};

class ResetVniCall final : BaseCall {
	ServerContext ctx_;
	ResetVniRequest request_;
	Status reply_;
	ServerAsyncResponseWriter<Status> responder_;

public:
	ResetVniCall(DPDKonmetal::AsyncService* service, ServerCompletionQueue* cq)
	: BaseCall(service, cq, DP_REQ_TYPE_VNI_RESET), responder_(&ctx_) {
		service_->RequestresetVni(&ctx_, &request_, &responder_, cq_, cq_,
														   this);
	}
	int Proceed() override;
};

class DelLBTargetPfxCall final : BaseCall {
	ServerContext ctx_;
	DeleteInterfaceLoadBalancerPrefixRequest request_;
	Status reply_;
	ServerAsyncResponseWriter<Status> responder_;

public:
	DelLBTargetPfxCall(DPDKonmetal::AsyncService* service, ServerCompletionQueue* cq)
	: BaseCall(service, cq, DP_REQ_TYPE_DEL_LBPREFIX), responder_(&ctx_) {
		service_->RequestdeleteInterfaceLoadBalancerPrefix(&ctx_, &request_, &responder_, cq_, cq_,
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
		service_->RequestlistInterfaceLoadBalancerPrefixes(&ctx_, &request_, &responder_, cq_, cq_,
														   this);
	}
	int Proceed() override;
};

class AddPfxCall final : BaseCall {
	ServerContext ctx_;
	InterfacePrefixMsg request_;
	IpAdditionResponse reply_;
	ServerAsyncResponseWriter<IpAdditionResponse> responder_;

public:
	AddPfxCall(DPDKonmetal::AsyncService* service, ServerCompletionQueue* cq)
	: BaseCall(service, cq, DP_REQ_TYPE_ADD_PREFIX), responder_(&ctx_) {
		service_->RequestaddInterfacePrefix(&ctx_, &request_, &responder_, cq_, cq_,
										 this);
	}
	int Proceed() override;
};

class DelPfxCall final : BaseCall {
	ServerContext ctx_;
	InterfacePrefixMsg request_;
	Status reply_;
	ServerAsyncResponseWriter<Status> responder_;

public:
	DelPfxCall(DPDKonmetal::AsyncService* service, ServerCompletionQueue* cq)
	: BaseCall(service, cq, DP_REQ_TYPE_DEL_PREFIX), responder_(&ctx_) {
		service_->RequestdeleteInterfacePrefix(&ctx_, &request_, &responder_, cq_, cq_,
										 this);
	}
	int Proceed() override;
};

class ListPfxCall final : BaseCall {
	ServerContext ctx_;
	InterfaceIDMsg request_;
	PrefixesMsg reply_;
	ServerAsyncResponseWriter<PrefixesMsg> responder_;
private:
	static void ListCallback(struct dpgrpc_reply *reply, void *context);
public:
	ListPfxCall(DPDKonmetal::AsyncService* service, ServerCompletionQueue* cq)
	: BaseCall(service, cq, DP_REQ_TYPE_LIST_PREFIXES), responder_(&ctx_) {
		service_->RequestlistInterfacePrefixes(&ctx_, &request_, &responder_, cq_, cq_,
										 this);
	}
	int Proceed() override;
};

class AddVIPCall final : BaseCall {
	ServerContext ctx_;
	InterfaceVIPMsg request_;
	IpAdditionResponse reply_;
	ServerAsyncResponseWriter<IpAdditionResponse> responder_;

public:
	AddVIPCall(DPDKonmetal::AsyncService* service, ServerCompletionQueue* cq)
	: BaseCall(service, cq, DP_REQ_TYPE_ADD_VIP), responder_(&ctx_) {
		service_->RequestaddInterfaceVIP(&ctx_, &request_, &responder_, cq_, cq_,
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
		service_->RequestcreateLoadBalancer(&ctx_, &request_, &responder_, cq_, cq_,
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
		service_->RequestgetLoadBalancer(&ctx_, &request_, &responder_, cq_, cq_,
											this);
	}
	int Proceed() override;
};

class DelLBCall final : BaseCall {
	ServerContext ctx_;
	DeleteLoadBalancerRequest request_;
	Status reply_;
	ServerAsyncResponseWriter<Status> responder_;

public:
	DelLBCall(DPDKonmetal::AsyncService* service, ServerCompletionQueue* cq)
	: BaseCall(service, cq, DP_REQ_TYPE_DEL_LB), responder_(&ctx_) {
		service_->RequestdeleteLoadBalancer(&ctx_, &request_, &responder_, cq_, cq_,
											this);
	}
	int Proceed() override;
};

class AddLBVIPCall final : BaseCall {
	ServerContext ctx_;
	AddLoadBalancerTargetRequest request_;
	Status reply_;
	ServerAsyncResponseWriter<Status> responder_;

public:
	AddLBVIPCall(DPDKonmetal::AsyncService* service, ServerCompletionQueue* cq)
	: BaseCall(service, cq, DP_REQ_TYPE_ADD_LBTARGET), responder_(&ctx_) {
		service_->RequestaddLoadBalancerTarget(&ctx_, &request_, &responder_, cq_, cq_,
											   this);
	}
	int Proceed() override;
};

class DelLBVIPCall final : BaseCall {
	ServerContext ctx_;
	DeleteLoadBalancerTargetRequest request_;
	Status reply_;
	ServerAsyncResponseWriter<Status> responder_;

public:
	DelLBVIPCall(DPDKonmetal::AsyncService* service, ServerCompletionQueue* cq)
	: BaseCall(service, cq, DP_REQ_TYPE_DEL_LBTARGET), responder_(&ctx_) {
		service_->RequestdeleteLoadBalancerTarget(&ctx_, &request_, &responder_, cq_, cq_,
												  this);
	}
	int Proceed() override;
};

class GetLBVIPBackendsCall final : BaseCall {
	ServerContext ctx_;
	GetLoadBalancerTargetsRequest request_;
	GetLoadBalancerTargetsResponse reply_;
	ServerAsyncResponseWriter<GetLoadBalancerTargetsResponse> responder_;
private:
	static void ListCallback(struct dpgrpc_reply *reply, void *context);
public:
	GetLBVIPBackendsCall(DPDKonmetal::AsyncService* service, ServerCompletionQueue* cq)
	: BaseCall(service, cq, DP_REQ_TYPE_LIST_LBTARGETS), responder_(&ctx_) {
		service_->RequestgetLoadBalancerTargets(&ctx_, &request_, &responder_, cq_, cq_,
												this);
	}
	int Proceed() override;
};

class DelVIPCall final : BaseCall {
	ServerContext ctx_;
	InterfaceIDMsg request_;
	Status reply_;
	ServerAsyncResponseWriter<Status> responder_;

public:
	DelVIPCall(DPDKonmetal::AsyncService* service, ServerCompletionQueue* cq)
	: BaseCall(service, cq, DP_REQ_TYPE_DEL_VIP), responder_(&ctx_) {
		service_->RequestdeleteInterfaceVIP(&ctx_, &request_, &responder_, cq_, cq_,
										 this);
	}
	int Proceed() override;
};

class GetVIPCall final : BaseCall {
	ServerContext ctx_;
	InterfaceIDMsg request_;
	InterfaceVIPIP reply_;
	ServerAsyncResponseWriter<InterfaceVIPIP> responder_;

public:
	GetVIPCall(DPDKonmetal::AsyncService* service, ServerCompletionQueue* cq)
	: BaseCall(service, cq, DP_REQ_TYPE_GET_VIP), responder_(&ctx_) {
		service_->RequestgetInterfaceVIP(&ctx_, &request_, &responder_, cq_, cq_,
										 this);
	}
	int Proceed() override;
};

class AddInterfaceCall final : BaseCall {
	ServerContext ctx_;
	CreateInterfaceRequest request_;
	CreateInterfaceResponse reply_;
	ServerAsyncResponseWriter<CreateInterfaceResponse> responder_;

public:
	AddInterfaceCall(DPDKonmetal::AsyncService* service, ServerCompletionQueue* cq)
	: BaseCall(service, cq, DP_REQ_TYPE_ADD_INTERFACE), responder_(&ctx_) {
		service_->RequestcreateInterface(&ctx_, &request_, &responder_, cq_, cq_,
										 this);
	}
	int Proceed() override;
};

class DelInterfaceCall final : BaseCall {
	ServerContext ctx_;
	InterfaceIDMsg request_;
	Status reply_;
	ServerAsyncResponseWriter<Status> responder_;

public:
	DelInterfaceCall(DPDKonmetal::AsyncService* service, ServerCompletionQueue* cq)
	: BaseCall(service, cq, DP_REQ_TYPE_DEL_INTERFACE), responder_(&ctx_) {
		service_->RequestdeleteInterface(&ctx_, &request_, &responder_, cq_, cq_,
										 this);
	}
	int Proceed() override;
};

class AddRouteCall final : BaseCall {
	ServerContext ctx_;
	VNIRouteMsg request_;
	Status reply_;
	ServerAsyncResponseWriter<Status> responder_;

public:
	AddRouteCall(DPDKonmetal::AsyncService* service, ServerCompletionQueue* cq)
	: BaseCall(service, cq, DP_REQ_TYPE_ADD_ROUTE), responder_(&ctx_) {
		service_->RequestaddRoute(&ctx_, &request_, &responder_, cq_, cq_,
										 this);
	}
	int Proceed() override;
};

class DelRouteCall final : BaseCall {
	ServerContext ctx_;
	VNIRouteMsg request_;
	Status reply_;
	ServerAsyncResponseWriter<Status> responder_;

public:
	DelRouteCall(DPDKonmetal::AsyncService* service, ServerCompletionQueue* cq)
	: BaseCall(service, cq, DP_REQ_TYPE_DEL_ROUTE), responder_(&ctx_) {
		service_->RequestdeleteRoute(&ctx_, &request_, &responder_, cq_, cq_,
										 this);
	}
	int Proceed() override;
};

class GetInterfaceCall final : BaseCall {
	ServerContext ctx_;
	InterfaceIDMsg request_;
	GetInterfaceResponse reply_;
	ServerAsyncResponseWriter<GetInterfaceResponse> responder_;

public:
	GetInterfaceCall(DPDKonmetal::AsyncService* service, ServerCompletionQueue* cq)
	: BaseCall(service, cq, DP_REQ_TYPE_GET_INTERFACE), responder_(&ctx_) {
		service_->RequestgetInterface(&ctx_, &request_, &responder_, cq_, cq_,
										 this);
	}
	int Proceed() override;
};

class ListRoutesCall final : BaseCall {
	ServerContext ctx_;
	VNIMsg request_;
	RoutesMsg reply_;
	ServerAsyncResponseWriter<RoutesMsg> responder_;
private:
	static void ListCallback(struct dpgrpc_reply *reply, void *context);
public:
	ListRoutesCall(DPDKonmetal::AsyncService* service, ServerCompletionQueue* cq)
	: BaseCall(service, cq, DP_REQ_TYPE_LIST_ROUTES), responder_(&ctx_) {
		service_->RequestlistRoutes(&ctx_, &request_, &responder_, cq_, cq_,
										 this);
	}
	int Proceed() override;
};

class ListInterfacesCall final : BaseCall {
	ServerContext ctx_;
	Empty request_;
	InterfacesMsg reply_;
	ServerAsyncResponseWriter<InterfacesMsg> responder_;
private:
	static void ListCallback(struct dpgrpc_reply *reply, void *context);
public:
	ListInterfacesCall(DPDKonmetal::AsyncService* service, ServerCompletionQueue* cq)
	: BaseCall(service, cq, DP_REQ_TYPE_LIST_INTERFACES), responder_(&ctx_) {
		service_->RequestlistInterfaces(&ctx_, &request_, &responder_, cq_, cq_,
										 this);
	}
	int Proceed() override;
};

class AddNATVIPCall final: BaseCall {
	ServerContext ctx_;
	AddNATRequest request_;
	AddNATResponse reply_;
	ServerAsyncResponseWriter<AddNATResponse> responder_;

public:
	AddNATVIPCall(DPDKonmetal::AsyncService* service, ServerCompletionQueue* cq)
	: BaseCall(service, cq, DP_REQ_TYPE_ADD_NAT), responder_(&ctx_) {
		service_->RequestaddNAT(&ctx_, &request_, &responder_, cq_, cq_,
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
		service_->RequestgetNATInfo(&ctx_, &request_, &responder_, cq_, cq_,
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
		service_->RequestgetNAT(&ctx_, &request_, &responder_, cq_, cq_,
								this);
	}
	int	Proceed() override;
};

class DeleteNATVIPCall final: BaseCall {
	ServerContext ctx_;
	DeleteNATRequest request_;
	Status reply_;
	ServerAsyncResponseWriter<Status> responder_;

public:
	DeleteNATVIPCall(DPDKonmetal::AsyncService* service, ServerCompletionQueue* cq)
	: BaseCall(service, cq, DP_REQ_TYPE_DEL_NAT), responder_(&ctx_) {
		service_->RequestdeleteNAT(&ctx_, &request_, &responder_, cq_, cq_,
										 this);
	}
	int	Proceed() override;
};

class AddNeighborNATCall final: BaseCall {
	ServerContext ctx_;
	AddNeighborNATRequest request_;
	Status reply_;
	ServerAsyncResponseWriter<Status> responder_;

public:
	AddNeighborNATCall(DPDKonmetal::AsyncService* service, ServerCompletionQueue* cq)
	: BaseCall(service, cq, DP_REQ_TYPE_ADD_NEIGHNAT), responder_(&ctx_) {
		service_->RequestaddNeighborNAT(&ctx_, &request_, &responder_, cq_, cq_,
										 this);
	}
	int	Proceed() override;
};

class DeleteNeighborNATCall final: BaseCall {
	ServerContext ctx_;
	DeleteNeighborNATRequest request_;
	Status reply_;
	ServerAsyncResponseWriter<Status> responder_;

public:
	DeleteNeighborNATCall(DPDKonmetal::AsyncService* service, ServerCompletionQueue* cq)
	: BaseCall(service, cq, DP_REQ_TYPE_DEL_NEIGHNAT), responder_(&ctx_) {
		service_->RequestdeleteNeighborNAT(&ctx_, &request_, &responder_, cq_, cq_,
										 this);
	}
	int	Proceed() override;
};

class InitializedCall final : BaseCall {
	ServerContext ctx_;
	Empty request_;
	UUIDMsg reply_;
	ServerAsyncResponseWriter<UUIDMsg> responder_;

public:
	InitializedCall(DPDKonmetal::AsyncService* service, ServerCompletionQueue* cq)
	: BaseCall(service, cq, DP_REQ_TYPE_INITIALIZED), responder_(&ctx_) {
		service_->Requestinitialized(&ctx_, &request_, &responder_, cq_, cq_,
										 this);
	}
	int Proceed() override;
};

class InitCall final : BaseCall {
	ServerContext ctx_;
	InitConfig request_;
	Status reply_;
	ServerAsyncResponseWriter<Status> responder_;

public:
	InitCall(DPDKonmetal::AsyncService* service, ServerCompletionQueue* cq)
	: BaseCall(service, cq, DP_REQ_TYPE_INIT), responder_(&ctx_) {
		service_->Requestinit(&ctx_, &request_, &responder_, cq_, cq_,
										 this);
	}
	int Proceed() override;
};

class AddFirewallRuleCall final : BaseCall {
	ServerContext ctx_;
	AddFirewallRuleRequest request_;
	AddFirewallRuleResponse reply_;
	ServerAsyncResponseWriter<AddFirewallRuleResponse> responder_;

public:
	AddFirewallRuleCall(DPDKonmetal::AsyncService* service, ServerCompletionQueue* cq)
	: BaseCall(service, cq, DP_REQ_TYPE_ADD_FWRULE), responder_(&ctx_) {
		service_->RequestaddFirewallRule(&ctx_, &request_, &responder_, cq_, cq_,
										 this);
	}
	int Proceed() override;
};

class DelFirewallRuleCall final : BaseCall {
	ServerContext ctx_;
	DeleteFirewallRuleRequest request_;
	Status reply_;
	ServerAsyncResponseWriter<Status> responder_;

public:
	DelFirewallRuleCall(DPDKonmetal::AsyncService* service, ServerCompletionQueue* cq)
	: BaseCall(service, cq, DP_REQ_TYPE_DEL_FWRULE), responder_(&ctx_) {
		service_->RequestdeleteFirewallRule(&ctx_, &request_, &responder_, cq_, cq_,
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
		service_->RequestgetFirewallRule(&ctx_, &request_, &responder_, cq_, cq_,
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
		service_->RequestlistFirewallRules(&ctx_, &request_, &responder_, cq_, cq_,
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
		service_->RequestgetVersion(&ctx_, &request_, &responder_, cq_, cq_,
									this);
	}
	int Proceed() override;
};

#endif //__INCLUDE_DP_ASYNC_GRPC_H__
