// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#ifndef __INCLUDE_DP_GRPC_SERVICE_H__
#define __INCLUDE_DP_GRPC_SERVICE_H__

#include "../proto/dpdk.grpc.pb.h"

#include <grpc/grpc.h>
#include <grpcpp/security/server_credentials.h>
#include <grpcpp/server.h>
#include <grpcpp/server_builder.h>
#include <grpcpp/server_context.h>
#include <uuid/uuid.h>

#define DP_UUID_SIZE 37

using grpc::Server;
using grpc::ServerCompletionQueue;

class GRPCService final : public dpdkonmetal::v1::DPDKonmetal::AsyncService {
private:
	static GRPCService* instance;
	GRPCService();
	~GRPCService();

	std::unique_ptr<ServerCompletionQueue> cq_;
	std::unique_ptr<Server> server_;
	uuid_t binuuid;
	char* uuid;
	bool initialized = false;

	void HandleRpcs();

public:
	GRPCService(const GRPCService& obj) = delete;
	static GRPCService* GetInstance();
	static void Cleanup();

	bool run(std::string listen_address);
	const char* GetUUID();
	void SetInitStatus(bool status);
	bool IsInitialized();
	ServerCompletionQueue* GetCq() { return cq_.get(); }
};

#endif
