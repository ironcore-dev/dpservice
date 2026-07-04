// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#ifndef __INCLUDE_DP_ASYNC_GRPC_ONMETAL_H__
#define __INCLUDE_DP_ASYNC_GRPC_ONMETAL_H__

#include "../proto/dpdk_onmetal.grpc.pb.h"

#include <grpc/grpc.h>
#include <grpcpp/security/server_credentials.h>
#include <grpcpp/server.h>
#include <grpcpp/server_builder.h>
#include <grpcpp/server_context.h>
#include "dp_error.h"
#include "../grpc/dp_grpc_api.h"
#include "dp_grpc_conv.hpp"
#include "dp_firewall.h"

// unfortunately, templates are not usable due to the fact that the RequestXxx() is always different
#define CREATE_CALLCLASS(NAME, BASE) \
class NAME ## CallOnmetal final : private BASE { \
private: \
	NAME ## Request request_; \
	NAME ## Response reply_; \
	ServerAsyncResponseWriter<NAME ## Response> responder_; \
	void Clone() override { \
		new NAME ## CallOnmetal(); \
	} \
	void Finish(const grpc::Status& status) override { \
		responder_.Finish(reply_, status, this); \
	} \
	void SetStatus(uint32_t grpc_errcode) override { \
		reply_.set_allocated_status(GrpcConvOnmetal::CreateStatus(grpc_errcode)); \
	} \
	const char* FillRequest(struct dpgrpc_request* request) override; \
	void ParseReply(struct dpgrpc_reply* reply) override; \
public: \
	NAME ## CallOnmetal() : BASE(DP_REQ_TYPE_ ## NAME), responder_(&ctx_) { \
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

#include "dp_grpc_service.hpp"

enum CallOnmetalState { REQUEST, AWAIT_MSG, FINISH };

class BaseCallOnmetal {
private:
	CallOnmetalState call_state_;

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
	GRPCServiceOnmetal *service_;
	ServerCompletionQueue *cq_;
	dpgrpc_request_type call_type_;
	ServerContext ctx_;

	BaseCallOnmetal(dpgrpc_request_type call_type)
		: call_state_(REQUEST),
		  service_(GRPCServiceOnmetal::GetInstance()),
		  cq_(service_->GetCq()),
		  call_type_(call_type)
		{}
	virtual ~BaseCallOnmetal() = default;

	// Generated for each message handler
	virtual void SetStatus(uint32_t grpc_errcode) = 0;

	// To be implemented by the message handlers proper (in .cpp)
	virtual const char* FillRequest(struct dpgrpc_request* request) = 0;
	virtual void ParseReply(struct dpgrpc_reply* reply) = 0;

public:
	CallOnmetalState HandleRpc();
};


// Variant for call that do not use the worker thread at all
class NoIpcCallOnmetal : protected BaseCallOnmetal {
private:
	int WriteRequest(struct dpgrpc_request *request) override;
	int HandleReply() override;
public:
	NoIpcCallOnmetal(dpgrpc_request_type call_type) : BaseCallOnmetal(call_type) {}
};


// Variant for calls with only one reply from worker thread
class SingleReplyCallOnmetal : protected BaseCallOnmetal {
private:
	int HandleReply() override;
public:
	SingleReplyCallOnmetal(dpgrpc_request_type call_type) : BaseCallOnmetal(call_type) {}
};


// Variant for calls with a chained reply from worker thread
class MultiReplyCallOnmetal : protected BaseCallOnmetal {
private:
	int HandleReply() override;
public:
	MultiReplyCallOnmetal(dpgrpc_request_type call_type) : BaseCallOnmetal(call_type) {}
};


// Special case for Initialize() as it does not need to be initialized to work
class InitCallOnmetal : protected SingleReplyCallOnmetal {
private:
	bool NeedsInit() override { return false; }
public:
	InitCallOnmetal(dpgrpc_request_type call_type) : SingleReplyCallOnmetal(call_type) {}
};


// Generated classes for each gRPC call
CREATE_CALLCLASS(Initialize, InitCallOnmetal);
CREATE_CALLCLASS(CheckInitialized, NoIpcCallOnmetal);

CREATE_CALLCLASS(GetVersion, SingleReplyCallOnmetal);

CREATE_CALLCLASS(CreateInterface, SingleReplyCallOnmetal);
CREATE_CALLCLASS(DeleteInterface, SingleReplyCallOnmetal);
CREATE_CALLCLASS(GetInterface, SingleReplyCallOnmetal);
CREATE_CALLCLASS(ListInterfaces, MultiReplyCallOnmetal);

CREATE_CALLCLASS(CreatePrefix, SingleReplyCallOnmetal);
CREATE_CALLCLASS(DeletePrefix, SingleReplyCallOnmetal);
CREATE_CALLCLASS(ListPrefixes, MultiReplyCallOnmetal);

CREATE_CALLCLASS(CreateRoute, SingleReplyCallOnmetal);
CREATE_CALLCLASS(DeleteRoute, SingleReplyCallOnmetal);
CREATE_CALLCLASS(ListRoutes, MultiReplyCallOnmetal);

CREATE_CALLCLASS(CreateVip, SingleReplyCallOnmetal);
CREATE_CALLCLASS(DeleteVip, SingleReplyCallOnmetal);
CREATE_CALLCLASS(GetVip, SingleReplyCallOnmetal);

CREATE_CALLCLASS(CreateNat, SingleReplyCallOnmetal);
CREATE_CALLCLASS(DeleteNat, SingleReplyCallOnmetal);
CREATE_CALLCLASS(GetNat, SingleReplyCallOnmetal);
CREATE_CALLCLASS(ListLocalNats, MultiReplyCallOnmetal);

CREATE_CALLCLASS(CreateNeighborNat, SingleReplyCallOnmetal);
CREATE_CALLCLASS(DeleteNeighborNat, SingleReplyCallOnmetal);
CREATE_CALLCLASS(ListNeighborNats, MultiReplyCallOnmetal);

CREATE_CALLCLASS(CreateLoadBalancer, SingleReplyCallOnmetal);
CREATE_CALLCLASS(DeleteLoadBalancer, SingleReplyCallOnmetal);
CREATE_CALLCLASS(GetLoadBalancer, SingleReplyCallOnmetal);
CREATE_CALLCLASS(ListLoadBalancers, MultiReplyCallOnmetal);

CREATE_CALLCLASS(CreateLoadBalancerTarget, SingleReplyCallOnmetal);
CREATE_CALLCLASS(DeleteLoadBalancerTarget, SingleReplyCallOnmetal);
CREATE_CALLCLASS(ListLoadBalancerTargets, MultiReplyCallOnmetal);

CREATE_CALLCLASS(CreateLoadBalancerPrefix, SingleReplyCallOnmetal);
CREATE_CALLCLASS(DeleteLoadBalancerPrefix, SingleReplyCallOnmetal);
CREATE_CALLCLASS(ListLoadBalancerPrefixes, MultiReplyCallOnmetal);

CREATE_CALLCLASS(CreateFirewallRule, SingleReplyCallOnmetal);
CREATE_CALLCLASS(DeleteFirewallRule, SingleReplyCallOnmetal);
CREATE_CALLCLASS(GetFirewallRule, SingleReplyCallOnmetal);
CREATE_CALLCLASS(ListFirewallRules, MultiReplyCallOnmetal);

CREATE_CALLCLASS(CheckVniInUse, SingleReplyCallOnmetal);
CREATE_CALLCLASS(ResetVni, SingleReplyCallOnmetal);

CREATE_CALLCLASS(CaptureStart, SingleReplyCallOnmetal);
CREATE_CALLCLASS(CaptureStop, SingleReplyCallOnmetal);
CREATE_CALLCLASS(CaptureStatus, SingleReplyCallOnmetal);

#endif
