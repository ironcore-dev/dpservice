#include <iostream>
#include <memory>
#include <string>

#include <grpcpp/grpcpp.h>

#include "../proto/dpdk.grpc.pb.h"

using grpc::Channel;
using grpc::ClientContext;
using dpdkonmetal::DPDKonmetal;
using dpdkonmetal::Status;
using dpdkonmetal::Empty;

class GRPCClient {
public:
	GRPCClient(std::shared_ptr<Channel> channel)
		: stub_(DPDKonmetal::NewStub(channel)) {}
		void SayHello() {
			Empty request;
			Status reply;
			ClientContext context;

			stub_->QueryHelloWorld(&context, request, &reply);
	}

private:
	std::unique_ptr<DPDKonmetal::Stub> stub_;
};

int main(int argc, char** argv) {
	GRPCClient greeter(grpc::CreateChannel(
		"localhost:1337", grpc::InsecureChannelCredentials()));
	greeter.SayHello();
	std::cout << "Hello called " << std::endl;

	return 0;
}
