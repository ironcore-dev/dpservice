#include "grpc/dp_grpc_service.h"
#include "grpc/dp_async_grpc.h"
#include "dp_util.h"
#include "dp_lpm.h"
#include "dp_port.h"
#include <rte_mbuf.h>


GRPCService::GRPCService()
{
}

GRPCService::~GRPCService()
{
}

void GRPCService::run(std::string listen_address) 
{
	ServerBuilder builder;
	builder.AddListeningPort(listen_address, grpc::InsecureServerCredentials());
	builder.RegisterService(this);
	this->cq_ = builder.AddCompletionQueue();
	this->server_= builder.BuildAndStart();
	std::cout << "Server listening on " << listen_address << std::endl;
	HandleRpcs();
}

void GRPCService::HandleRpcs()
{
	void* tag;
	bool ok;
	new DelPfxCall(this, cq_.get());
	new ListPfxCall(this, cq_.get());
	new AddPfxCall(this, cq_.get());
	new GetLBVIPBackendsCall(this, cq_.get());
	new AddLBVIPCall(this, cq_.get());
	new DelLBVIPCall(this, cq_.get());
	new AddVIPCall(this, cq_.get());
	new DelVIPCall(this, cq_.get());
	new GetVIPCall(this, cq_.get());
	new AddRouteCall(this, cq_.get());
	new DelRouteCall(this, cq_.get());
	new ListRoutesCall(this, cq_.get());
	new AddMachineCall(this, cq_.get());
	new DelMachineCall(this, cq_.get());
	new ListMachinesCall(this, cq_.get());

	while (true) {
		GPR_ASSERT(cq_->Next(&tag, &ok));
		GPR_ASSERT(ok);
		while (static_cast<BaseCall*>(tag)->Proceed() < 0) {};
	}
}
