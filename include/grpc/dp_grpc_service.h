#ifndef __INCLUDE_DP_GRPC_SERVICE_H
#define __INCLUDE_DP_GRPC_SERVICE_H

#include "../proto/dpdk.grpc.pb.h"


#include <grpc/grpc.h>
#include <grpcpp/security/server_credentials.h>
#include <grpcpp/server.h>
#include <grpcpp/server_builder.h>
#include <grpcpp/server_context.h>
#include "dp_async_grpc.h"
#include <uuid/uuid.h>

#define DP_UUID_SIZE 37

class GRPCService final : public DPDKonmetal::AsyncService {
private:
	std::unique_ptr<ServerCompletionQueue> cq_;
	std::unique_ptr<Server> server_;
	uuid_t binuuid;
	void *uuid;
	uint16_t pfx_counter = 1;
	bool initialized = false;
	
public:
	GRPCService();
	~GRPCService();
	void run(std::string listen_address);
	void HandleRpcs();
	char* GetUUID();
	void SetInitStatus(bool status);
	bool IsInitialized();
	void CalculateUnderlayRoute(uint32_t vni, uint8_t* route, uint32_t route_size);
};

#endif //__INCLUDE_DP_GRPC_SERVICE_H