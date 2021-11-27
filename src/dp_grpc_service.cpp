#include "dp_grpc_service.h"


void GRPCService::run(std::string listen_address) {
	ServerBuilder builder;
	builder.AddListeningPort(listen_address, grpc::InsecureServerCredentials());
	builder.RegisterService(this);
	std::unique_ptr<Server> server(builder.BuildAndStart());
	std::cout << "Server listening on " << listen_address << std::endl;
	server->Wait();
}

grpc::Status GRPCService::QueryHelloWorld(ServerContext* context, const Empty* request, Status* response) {
	std::cout << "Hello World !! " << std::endl;
	return grpc::Status::OK;
}
