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

using dpdkonmetal::PrintHelloWorldService;
using dpdkonmetal::Status;
using dpdkonmetal::Empty;

class GRPCService final : public PrintHelloWorldService::Service {
private:
	struct dp_dpdk_layer* dpdk_layer;
public:
	explicit GRPCService(struct dp_dpdk_layer* dp_layer);
	void run(std::string listen_address);
	grpc::Status QueryHelloWorld(ServerContext* context, const Empty* request, Status* response) override;
};

#endif //__INCLUDE_DP_GRPC_SERVICE_H