#include "dp_grpc_service.h"
#include "dp_util.h"
#include "dp_lpm.h"
#include "dp_port.h"
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

grpc::Status GRPCService::addMachine(ServerContext* context, const AddMachineRequest* request, AddMachineResponse* response)
{
	char machine_id_bytes[VM_MACHINE_ID_STR_LEN] = {0};
	struct dp_port_ext pf_port;
	IPConfig ipv4_conf;
	IPConfig ipv6_conf;
	int vni, port_id;
	struct in_addr ip_addr;
	uint8_t ipv6_addr[16];

	std::cout << "GRPC AddMachine called !! " << std::endl;
	memset(&pf_port, 0, sizeof(pf_port));
	memcpy(pf_port.port_name, dp_get_pf0_name(), IFNAMSIZ);

	vni = request->vni();
	ipv4_conf = request->ipv4config();
	inet_aton(ipv4_conf.primaryaddress().c_str(), &ip_addr);
	ipv6_conf = request->ipv6config();
	uint8_t ret = inet_pton(AF_INET6, ipv6_conf.primaryaddress().c_str(), &ipv6_addr);
	if(ret < 0)
		printf("IPv6 address not in proper format\n");

	printf("VNI %d  IPv4 %x\n", vni, ntohl(ip_addr.s_addr));

	snprintf(machine_id_bytes, VM_MACHINE_ID_STR_LEN, "%s", request->machineid().c_str());
	port_id = dp_get_next_avail_vf_id(this->dpdk_layer, DP_PORT_VF);
	if ( port_id >= 0) {
		dp_map_vm_handle(machine_id_bytes, port_id);
		setup_lpm(port_id, vni, rte_eth_dev_socket_id(port_id));
		setup_lpm6(port_id, vni, rte_eth_dev_socket_id(port_id));
		dp_set_dhcp_range_ip4(port_id, ntohl(ip_addr.s_addr), 32, rte_eth_dev_socket_id(port_id));
		dp_set_dhcp_range_ip6(port_id, ipv6_addr, 128, rte_eth_dev_socket_id(port_id));
		dp_add_route(port_id, vni, 0, ntohl(ip_addr.s_addr), NULL, 32, rte_eth_dev_socket_id(port_id));
		dp_add_route6(port_id, vni, 0,ipv6_addr , NULL, 128, rte_eth_dev_socket_id(port_id));
		dp_start_interface(&pf_port, DP_PORT_VF);
	} else {
		printf("Invalid port id: %d\n",port_id);
	}
	return grpc::Status::OK;
}

grpc::Status GRPCService::addMachineVIP(ServerContext* context, const MachineVIPMsg* request, Status* response)
{
	char machine_id_bytes[VM_MACHINE_ID_STR_LEN] = {0};
	struct in_addr vip_addr;
	int port_id;

	snprintf(machine_id_bytes, VM_MACHINE_ID_STR_LEN, "%s", request->machineid().c_str());
	port_id = dp_get_portid_with_vm_handle(machine_id_bytes);

	/* This machine ID doesnt exist */
	if (port_id < 0)
		return grpc::Status::CANCELLED;

	if (request->machinevipip().ipversion() == dpdkonmetal::IPVersion::IPv4) {
		inet_aton(request->machinevipip().address().c_str(), &vip_addr);
		dp_set_vm_nat_ip(port_id, ntohl(vip_addr.s_addr));
	}

	return grpc::Status::OK;
}

grpc::Status GRPCService::getMachineVIP(ServerContext* context, const MachineIDMsg* request, MachineVIPIP* response)
{
	return grpc::Status::OK;
}

grpc::Status GRPCService::delMachineVIP(ServerContext* context, const MachineIDMsg* request, Status* response)
{
	char machine_id_bytes[VM_MACHINE_ID_STR_LEN] = {0};
	int port_id;

	snprintf(machine_id_bytes, VM_MACHINE_ID_STR_LEN, "%s", request->machineid().c_str());
	port_id = dp_get_portid_with_vm_handle(machine_id_bytes);

	/* This machine ID doesnt exist */
	if (port_id < 0)
		return grpc::Status::CANCELLED;

	dp_del_vm_nat_ip(port_id);

	return grpc::Status::OK;
}
