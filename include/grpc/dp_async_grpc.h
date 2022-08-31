#ifndef __INCLUDE_DP_ASYNC_GRPC_SERVICE_H
#define __INCLUDE_DP_ASYNC_GRPC_SERVICE_H

#include "../proto/dpdk.grpc.pb.h"


#include <grpc/grpc.h>
#include <grpcpp/security/server_credentials.h>
#include <grpcpp/server.h>
#include <grpcpp/server_builder.h>
#include <grpcpp/server_context.h>
#include "dp_grpc_impl.h"

using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::ServerReader;
using grpc::ServerReaderWriter;
using grpc::ServerWriter;

using grpc::ServerAsyncResponseWriter;
using grpc::ServerCompletionQueue;

using namespace dpdkonmetal;

enum CallStatus { REQUEST, AWAIT_MSG, FINISH };

class BaseCall {
protected:
	DPDKonmetal::AsyncService* service_;
	ServerCompletionQueue* cq_;
	CallStatus status_;
	uint16_t call_type_;
public:
	BaseCall(DPDKonmetal::AsyncService* service, ServerCompletionQueue* cq, uint16_t call_type)
		: service_(service), cq_(cq), status_(REQUEST), call_type_(call_type) {
		}
	virtual int Proceed() = 0;
	virtual ~BaseCall() = default;
};

class AddPfxCall final : BaseCall {
	ServerContext ctx_;
	InterfacePrefixMsg request_;
	IpAdditionResponse reply_;
	ServerAsyncResponseWriter<IpAdditionResponse> responder_;

public:
	AddPfxCall(DPDKonmetal::AsyncService* service, ServerCompletionQueue* cq)
	:BaseCall(service, cq, DP_REQ_TYPE_ADDPREFIX), responder_(&ctx_) {
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
	:BaseCall(service, cq, DP_REQ_TYPE_DELPREFIX), responder_(&ctx_) {
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

public:
	ListPfxCall(DPDKonmetal::AsyncService* service, ServerCompletionQueue* cq)
	:BaseCall(service, cq, DP_REQ_TYPE_LISTPREFIX), responder_(&ctx_) {
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
	:BaseCall(service, cq, DP_REQ_TYPE_ADDVIP), responder_(&ctx_) {
		service_->RequestaddInterfaceVIP(&ctx_, &request_, &responder_, cq_, cq_,
										 this);
	}
	int Proceed() override;
};

class AddLBVIPCall final : BaseCall {
	ServerContext ctx_;
	LBMsg request_;
	IpAdditionResponse reply_;
	ServerAsyncResponseWriter<IpAdditionResponse> responder_;

public:
	AddLBVIPCall(DPDKonmetal::AsyncService* service, ServerCompletionQueue* cq)
	:BaseCall(service, cq, DP_REQ_TYPE_ADDLBVIP), responder_(&ctx_) {
		service_->RequestaddLBVIP(&ctx_, &request_, &responder_, cq_, cq_,
										 this);
	}
	int Proceed() override;
};

class DelLBVIPCall final : BaseCall {
	ServerContext ctx_;
	LBMsg request_;
	Status reply_;
	ServerAsyncResponseWriter<Status> responder_;

public:
	DelLBVIPCall(DPDKonmetal::AsyncService* service, ServerCompletionQueue* cq)
	:BaseCall(service, cq, DP_REQ_TYPE_DELLBVIP), responder_(&ctx_) {
		service_->RequestdelLBVIP(&ctx_, &request_, &responder_, cq_, cq_,
										 this);
	}
	int Proceed() override;
};

class GetLBVIPBackendsCall final : BaseCall {
	ServerContext ctx_;
	LBQueryMsg request_;
	LBBackendMsg reply_;
	ServerAsyncResponseWriter<LBBackendMsg> responder_;

public:
	GetLBVIPBackendsCall(DPDKonmetal::AsyncService* service, ServerCompletionQueue* cq)
	:BaseCall(service, cq, DP_REQ_TYPE_LISTLBBACKENDS), responder_(&ctx_) {
		service_->RequestgetLBVIPBackends(&ctx_, &request_, &responder_, cq_, cq_,
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
	:BaseCall(service, cq, DP_REQ_TYPE_DELVIP), responder_(&ctx_) {
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
	:BaseCall(service, cq, DP_REQ_TYPE_GETVIP), responder_(&ctx_) {
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
	:BaseCall(service, cq, DP_REQ_TYPE_ADDMACHINE), responder_(&ctx_) {
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
	:BaseCall(service, cq, DP_REQ_TYPE_DELMACHINE), responder_(&ctx_) {
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
	:BaseCall(service, cq, DP_REQ_TYPE_ADDROUTE), responder_(&ctx_) {
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
	:BaseCall(service, cq, DP_REQ_TYPE_DELROUTE), responder_(&ctx_) {
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
	:BaseCall(service, cq, DP_REQ_TYPE_GETMACHINE), responder_(&ctx_) {
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

public:
	ListRoutesCall(DPDKonmetal::AsyncService* service, ServerCompletionQueue* cq)
	:BaseCall(service, cq, DP_REQ_TYPE_LISTROUTE), responder_(&ctx_) {
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

public:
	ListInterfacesCall(DPDKonmetal::AsyncService* service, ServerCompletionQueue* cq)
	:BaseCall(service, cq, DP_REQ_TYPE_LISTMACHINE), responder_(&ctx_) {
		service_->RequestlistInterfaces(&ctx_, &request_, &responder_, cq_, cq_,
										 this);
	}
	int Proceed() override;
};

class InitializedCall final : BaseCall {
	ServerContext ctx_;
	Empty request_;
	UUIDMsg reply_;
	ServerAsyncResponseWriter<UUIDMsg> responder_;

public:
	InitializedCall(DPDKonmetal::AsyncService* service, ServerCompletionQueue* cq)
	:BaseCall(service, cq, DP_REQ_TYPE_INIT), responder_(&ctx_) {
		service_->Requestinitialized(&ctx_, &request_, &responder_, cq_, cq_,
										 this);
	}
	int Proceed() override;
};
#endif //__INCLUDE_DP_ASYNC_GRPC_SERVICE_H