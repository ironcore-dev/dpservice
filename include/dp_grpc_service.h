#ifndef __INCLUDE_DP_GRPC_SERVICE_H
#define __INCLUDE_DP_GRPC_SERVICE_H

#include "../proto/dpdk.grpc.pb.h"


#include <grpc/grpc.h>
#include <grpcpp/security/server_credentials.h>
#include <grpcpp/server.h>
#include <grpcpp/server_builder.h>
#include <grpcpp/server_context.h>
#include "dp_async_grpc.h"


class GRPCService final : public DPDKonmetal::AsyncService {
private:
	std::unique_ptr<ServerCompletionQueue> cq_;
	std::unique_ptr<Server> server_;
	
public:
	GRPCService();
	~GRPCService();
	void run(std::string listen_address);
	void HandleRpcs();
	grpc::Status deleteMachine(ServerContext* context, const MachineIDMsg* request, Status* response) override;
	grpc::Status addRoute(ServerContext* context, const VNIRouteMsg* request, Status* response) override;
	grpc::Status getMachineVIP(ServerContext* context, const MachineIDMsg* request, MachineVIPIP* response) override;
	grpc::Status delMachineVIP(ServerContext* context, const MachineIDMsg* request, Status* response) override;
};

#endif //__INCLUDE_DP_GRPC_SERVICE_H