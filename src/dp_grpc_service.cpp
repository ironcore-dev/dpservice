#include "dp_grpc_service.h"
#include "dp_async_grpc.h"
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
	new HelloCall(this, cq_.get());
	new AddVIPCall(this, cq_.get());
	new DelVIPCall(this, cq_.get());
	new AddMachineCall(this, cq_.get());
	new DelMachineCall(this, cq_.get());

	while (true) {
		GPR_ASSERT(cq_->Next(&tag, &ok));
		GPR_ASSERT(ok);
		while (static_cast<BaseCall*>(tag)->Proceed() < 0) {};
	}
}

grpc::Status GRPCService::addRoute(ServerContext* context, const VNIRouteMsg* request, Status* response)
{
	int vni, t_vni, port_id = 0;
	uint8_t t_ip6[16];
	struct in_addr ip_addr;
	uint8_t ip6_addr[16];
	Route route;
	VNIMsg vni_msg;
	Prefix prefix;

	vni_msg = request->vni();
	route = request->route();
	prefix = route.prefix();
	vni = vni_msg.vni();
	t_vni = route.nexthopvni();

	inet_pton(AF_INET6, route.nexthopaddress().c_str(), t_ip6);

	if(prefix.ipversion() == dpdkonmetal::IPVersion::IPv4) {
		inet_aton(prefix.address().c_str(), &ip_addr);
		dp_add_route(dp_get_pf0_port_id(), vni, t_vni, ntohl(ip_addr.s_addr), t_ip6, prefix.prefixlength(), rte_eth_dev_socket_id(port_id));
		printf("VNI %d  IPv4 %x length %d target ip6 %s target vni %d\n", vni, ntohl(ip_addr.s_addr), 
		    prefix.prefixlength(), route.nexthopaddress().c_str(), t_vni);
	}
	else {
		inet_pton(AF_INET6, prefix.address().c_str(), ip6_addr);
		dp_add_route6(dp_get_pf0_port_id(), vni, t_vni, ip6_addr, t_ip6, prefix.prefixlength(), rte_eth_dev_socket_id(port_id));
		printf("VNI %d  IPv6 %s length %d target ip6 %s target vni %d\n", vni, prefix.address().c_str(), 
		    prefix.prefixlength(), route.nexthopaddress().c_str(), t_vni);
	}



	return grpc::Status::OK;
}

grpc::Status GRPCService::getMachineVIP(ServerContext* context, const MachineIDMsg* request, MachineVIPIP* response)
{
	return grpc::Status::OK;
}
