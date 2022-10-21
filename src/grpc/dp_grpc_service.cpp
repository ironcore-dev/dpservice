#include "grpc/dp_grpc_service.h"
#include "grpc/dp_async_grpc.h"
#include "dp_util.h"
#include "dp_lpm.h"
#include "dp_port.h"
#include "dpdk_layer.h"
#include <rte_mbuf.h>


GRPCService::GRPCService()
{
	uuid = malloc(DP_UUID_SIZE);
	uuid_generate_random(binuuid);
	uuid_unparse_upper(binuuid, (char*)uuid);
}

GRPCService::~GRPCService()
{
	free(uuid);
}

void GRPCService::run(std::string listen_address)
{
	ServerBuilder builder;
	builder.AddListeningPort(listen_address, grpc::InsecureServerCredentials());
	builder.RegisterService(this);
	this->cq_ = builder.AddCompletionQueue();
	this->server_= builder.BuildAndStart();
	DPS_LOG(INFO, DPSERVICE, "Server initialized and listening on %s\n", listen_address.c_str());
	HandleRpcs();
}

char* GRPCService::GetUUID()
{
	return (char*)uuid;
}

void GRPCService::SetInitStatus(bool status)
{
	initialized = status;
}

bool GRPCService::IsInitialized()
{
	return initialized;
}

void GRPCService::CalculateUnderlayRoute(uint32_t vni, uint8_t* route, uint32_t route_size)
{
	uint32_t l_vni = htonl(vni);

	memcpy(route, get_underlay_conf()->src_ip6, route_size);
	memcpy(route + 8, &l_vni, 4);
	if (vni == 0) {
		memcpy(route + 12, &pfx_counter, 2);
		memset(route + 14, 0, 2);
	} else {
		memset(route + 12, 0, 4);
	}
	pfx_counter++;
}

void GRPCService::HandleRpcs()
{
	void* tag;
	bool ok;

	new InitCall(this, cq_.get());
	new InitializedCall(this, cq_.get());
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
	new AddInterfaceCall(this, cq_.get());
	new DelInterfaceCall(this, cq_.get());
	new ListInterfacesCall(this, cq_.get());
	new GetInterfaceCall(this, cq_.get());
	new CreateLBCall(this, cq_.get());
	new GetLBCall(this, cq_.get());
	new DelLBCall(this, cq_.get());
	new AddNATVIPCall(this, cq_.get());
	new DeleteNATVIPCall(this, cq_.get());
	new AddNeighborNATCall(this, cq_.get());
	new DeleteNeighborNATCall(this, cq_.get());
	new GetNATInfoCall(this, cq_.get());
	new ListLBTargetPfxCall(this, cq_.get());
	new DelLBTargetPfxCall(this, cq_.get());
	new CreateLBTargetPfxCall(this, cq_.get());

	while (true) {
		GPR_ASSERT(cq_->Next(&tag, &ok));
		GPR_ASSERT(ok);
		while (static_cast<BaseCall*>(tag)->Proceed() < 0) {};
	}
}

