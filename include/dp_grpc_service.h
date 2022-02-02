#ifndef __INCLUDE_DP_GRPC_SERVICE_H
#define __INCLUDE_DP_GRPC_SERVICE_H

#include "../proto/dpdk.grpc.pb.h"


#include <grpc/grpc.h>
#include <grpcpp/security/server_credentials.h>
#include <grpcpp/server.h>
#include <grpcpp/server_builder.h>
#include <grpcpp/server_context.h>
#include "dpdk_layer.h"

using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::ServerReader;
using grpc::ServerReaderWriter;
using grpc::ServerWriter;

using namespace dpdkonmetal;

class GRPCService final : public DPDKonmetal::Service {
private:
	struct dp_dpdk_layer* dpdk_layer;
public:
	explicit GRPCService(struct dp_dpdk_layer* dp_layer);
	void run(std::string listen_address);
	grpc::Status QueryHelloWorld(ServerContext* context, const Empty* request, Status* response) override;
	grpc::Status addMachine(ServerContext* context, const AddMachineRequest* request, AddMachineResponse* response) override;
	grpc::Status deleteMachine(ServerContext* context, const MachineIDMsg* request, Status* response) override;
	grpc::Status addRoute(ServerContext* context, const VNIRouteMsg* request, Status* response) override;
	grpc::Status addMachineVIP(ServerContext* context, const MachineVIPMsg* request, Status* response) override;
	grpc::Status getMachineVIP(ServerContext* context, const MachineIDMsg* request, MachineVIPIP* response) override;
	grpc::Status delMachineVIP(ServerContext* context, const MachineIDMsg* request, Status* response) override;
};

#endif //__INCLUDE_DP_GRPC_SERVICE_H