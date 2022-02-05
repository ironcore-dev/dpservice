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

class HelloCall final : BaseCall {
	ServerContext ctx_;
	Empty request_;
	Status reply_;
	ServerAsyncResponseWriter<Status> responder_;

public:
	HelloCall(DPDKonmetal::AsyncService* service, ServerCompletionQueue* cq)
	:BaseCall(service, cq, DP_REQ_TYPE_HELLO), responder_(&ctx_) {
		service_->RequestQueryHelloWorld(&ctx_, &request_, &responder_, cq_, cq_,
										 this);
	}
	int Proceed() override;
};

class AddVIPCall final : BaseCall {
	ServerContext ctx_;
	MachineVIPMsg request_;
	Status reply_;
	ServerAsyncResponseWriter<Status> responder_;

public:
	AddVIPCall(DPDKonmetal::AsyncService* service, ServerCompletionQueue* cq)
	:BaseCall(service, cq, DP_REQ_TYPE_ADDVIP), responder_(&ctx_) {
		service_->RequestaddMachineVIP(&ctx_, &request_, &responder_, cq_, cq_,
										 this);
	}
	int Proceed() override;
};

class AddMachineCall final : BaseCall {
	ServerContext ctx_;
	AddMachineRequest request_;
	AddMachineResponse reply_;
	ServerAsyncResponseWriter<AddMachineResponse> responder_;

public:
	AddMachineCall(DPDKonmetal::AsyncService* service, ServerCompletionQueue* cq)
	:BaseCall(service, cq, DP_REQ_TYPE_ADDMACHINE), responder_(&ctx_) {
		service_->RequestaddMachine(&ctx_, &request_, &responder_, cq_, cq_,
										 this);
	}
	int Proceed() override;
};

#endif //__INCLUDE_DP_ASYNC_GRPC_SERVICE_H