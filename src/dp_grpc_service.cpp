#include "dp_grpc_service.h"
#include <rte_mbuf.h>


GRPCService::GRPCService(struct dp_dpdk_layer* dp_layer)
{
	this->dpdk_layer = dp_layer;
}

void GRPCService::run(std::string listen_address) 
{
	ServerBuilder builder;
	builder.AddListeningPort(listen_address, grpc::InsecureServerCredentials());
	builder.RegisterService(this);
	std::unique_ptr<Server> server(builder.BuildAndStart());
	std::cout << "Server listening on " << listen_address << std::endl;
	server->Wait();
}

grpc::Status GRPCService::QueryHelloWorld(ServerContext* context, const Empty* request, Status* response)
{
	rte_mbuf *grpc_buf;
	int *test_value;

	std::cout << "GRPC method called !! " << std::endl;

	grpc_buf = rte_pktmbuf_alloc(this->dpdk_layer->rte_mempool);
	test_value = rte_pktmbuf_mtod(grpc_buf, int*);
	*test_value = 0xdeadbeef;

	if (rte_ring_sp_enqueue(this->dpdk_layer->grpc_queue, grpc_buf))
		return grpc::Status::CANCELLED;
	return grpc::Status::OK;
}

grpc::Status GRPCService::addMachine(ServerContext* context, const AddMachineRequest* request, AddMachineResponse* response)
{
	return grpc::Status::OK;
}

