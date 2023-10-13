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
#include "dp_grpc_conv.h"
#include "dp_firewall.h"

// unfortunately, templates are not usable due to the fact that the RequestXxx() is always different
#define CREATE_CALLCLASS(NAME, BASE) \
class NAME ## Call final : private BASE { \
private: \
	NAME ## Request request_; \
	NAME ## Response reply_; \
	ServerAsyncResponseWriter<NAME ## Response> responder_; \
	void Clone() override { \
		new NAME ## Call(); \
	} \
	void Finish(const grpc::Status& status) override { \
		responder_.Finish(reply_, status, this); \
	} \
	void SetStatus(uint32_t grpc_errcode) override { \
		reply_.set_allocated_status(GrpcConv::CreateStatus(grpc_errcode)); \
	} \
	const char* FillRequest(struct dpgrpc_request* request) override; \
	void ParseReply(struct dpgrpc_reply* reply) override; \
public: \
	NAME ## Call() : BASE(DP_REQ_TYPE_ ## NAME), responder_(&ctx_) { \
		service_->Request ## NAME(&ctx_, &request_, &responder_, cq_, cq_, this); \
	} \
}

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

enum CallState { REQUEST, AWAIT_MSG, FINISH };

class BaseCall {
private:
	CallState call_state_;

	// Sends the request to worker thread (override to prevent this)
	virtual int WriteRequest(struct dpgrpc_request *request);
	// Reads a (possibly chained) response from worker (needs single/multi implementation variants)
	virtual int HandleReply() = 0;
	// Indicates that gRPC call to Initialize() is required before running this call (override to disable)
	virtual bool NeedsInit() { return !service_->IsInitialized(); }

	// Generated for each message handler
	virtual void Clone() = 0;
	virtual void Finish(const grpc::Status& status) = 0;

protected:
	GRPCService *service_;
	ServerCompletionQueue *cq_;
	dpgrpc_request_type call_type_;
	ServerContext ctx_;

	BaseCall(dpgrpc_request_type call_type)
		: call_state_(REQUEST),
		  service_(GRPCService::GetInstance()),
		  cq_(service_->GetCq()),
		  call_type_(call_type)
		{}
	virtual ~BaseCall() = default;

	// Generated for each message handler
	virtual void SetStatus(uint32_t grpc_errcode) = 0;

	// To be implemented by the message handlers proper (in .cpp)
	virtual const char* FillRequest(struct dpgrpc_request* request) = 0;
	virtual void ParseReply(struct dpgrpc_reply* reply) = 0;

public:
	CallState HandleRpc();
};


// Variant for call that do not use the worker thread at all
class NoIpcCall : protected BaseCall {
private:
	int WriteRequest(struct dpgrpc_request *request) override;
	int HandleReply() override;
public:
	NoIpcCall(dpgrpc_request_type call_type) : BaseCall(call_type) {}
};


// Variant for calls with only one reply from worker thread
class SingleReplyCall : protected BaseCall {
private:
	int HandleReply() override;
public:
	SingleReplyCall(dpgrpc_request_type call_type) : BaseCall(call_type) {}
};


// Variant for calls with a chained reply from worker thread
class MultiReplyCall : protected BaseCall {
private:
	int HandleReply() override;
public:
	MultiReplyCall(dpgrpc_request_type call_type) : BaseCall(call_type) {}
};


// Special case for Initialize() as it does not need to be initialized to work
class InitCall : protected SingleReplyCall {
private:
	bool NeedsInit() override { return false; }
public:
	InitCall(dpgrpc_request_type call_type) : SingleReplyCall(call_type) {}
};


// Generated classes for each gRPC call
CREATE_CALLCLASS(Initialize, InitCall);
CREATE_CALLCLASS(CheckInitialized, NoIpcCall);

CREATE_CALLCLASS(GetVersion, SingleReplyCall);

CREATE_CALLCLASS(CreateInterface, SingleReplyCall);
CREATE_CALLCLASS(DeleteInterface, SingleReplyCall);
CREATE_CALLCLASS(GetInterface, SingleReplyCall);
CREATE_CALLCLASS(ListInterfaces, MultiReplyCall);

CREATE_CALLCLASS(CreatePrefix, SingleReplyCall);
CREATE_CALLCLASS(DeletePrefix, SingleReplyCall);
CREATE_CALLCLASS(ListPrefixes, MultiReplyCall);

CREATE_CALLCLASS(CreateRoute, SingleReplyCall);
CREATE_CALLCLASS(DeleteRoute, SingleReplyCall);
CREATE_CALLCLASS(ListRoutes, MultiReplyCall);

CREATE_CALLCLASS(CreateVip, SingleReplyCall);
CREATE_CALLCLASS(DeleteVip, SingleReplyCall);
CREATE_CALLCLASS(GetVip, SingleReplyCall);

CREATE_CALLCLASS(CreateNat, SingleReplyCall);
CREATE_CALLCLASS(DeleteNat, SingleReplyCall);
CREATE_CALLCLASS(GetNat, SingleReplyCall);
CREATE_CALLCLASS(ListLocalNats, MultiReplyCall);

CREATE_CALLCLASS(CreateNeighborNat, SingleReplyCall);
CREATE_CALLCLASS(DeleteNeighborNat, SingleReplyCall);
CREATE_CALLCLASS(ListNeighborNats, MultiReplyCall);

CREATE_CALLCLASS(CreateLoadBalancer, SingleReplyCall);
CREATE_CALLCLASS(DeleteLoadBalancer, SingleReplyCall);
CREATE_CALLCLASS(GetLoadBalancer, SingleReplyCall);

CREATE_CALLCLASS(CreateLoadBalancerTarget, SingleReplyCall);
CREATE_CALLCLASS(DeleteLoadBalancerTarget, SingleReplyCall);
CREATE_CALLCLASS(ListLoadBalancerTargets, MultiReplyCall);

CREATE_CALLCLASS(CreateLoadBalancerPrefix, SingleReplyCall);
CREATE_CALLCLASS(DeleteLoadBalancerPrefix, SingleReplyCall);
CREATE_CALLCLASS(ListLoadBalancerPrefixes, MultiReplyCall);

CREATE_CALLCLASS(CreateFirewallRule, SingleReplyCall);
CREATE_CALLCLASS(DeleteFirewallRule, SingleReplyCall);
CREATE_CALLCLASS(GetFirewallRule, SingleReplyCall);
CREATE_CALLCLASS(ListFirewallRules, MultiReplyCall);

CREATE_CALLCLASS(CheckVniInUse, SingleReplyCall);
CREATE_CALLCLASS(ResetVni, SingleReplyCall);

// CREATE_CALLCLASS(CaptureInit, SingleReplyCall);
// CREATE_CALLCLASS(CaptureSetInterface, SingleReplyCall);
CREATE_CALLCLASS(CaptureStart, SingleReplyCall);
CREATE_CALLCLASS(CaptureStop, SingleReplyCall);

#endif
