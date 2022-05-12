#include <iostream>
#include <getopt.h>
#include <memory>
#include <string>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


#include <grpcpp/grpcpp.h>

#include "../proto/dpdk.grpc.pb.h"

using grpc::Channel;
using grpc::ClientContext;
using namespace dpdkonmetal;

static const char short_options[] = "d" /* debug */
				    "D"	 /* promiscuous */;

typedef enum {
	DP_CMD_NONE,
	DP_CMD_ADD_MACHINE,
	DP_CMD_DEL_MACHINE,
	DP_CMD_GET_MACHINE,
	DP_CMD_ADD_ROUTE,
	DP_CMD_DEL_ROUTE,
	DP_CMD_GET_ROUTE,
	DP_CMD_ADD_VIP,
	DP_CMD_DEL_VIP,
	DP_CMD_GET_VIP,
	DP_CMD_ADD_LB_VIP,
	DP_CMD_DEL_LB_VIP,
} cmd_type;

static char ip6_str[40] = {0};
static char t_ip6_str[40] = {0};
static char vni_str[30] = {0};
static char len_str[30] = {0};
static char t_vni_str[30] = {0};
static char machine_str[30] = {0};
static char ip_str[30] = {0};
static char back_ip_str[30] = {0};
static char pxe_ip_str[30] = {0};
static char pxe_path_str[30] = {0};
static IPVersion version;

static int command;
static int debug_mode;
static int vni;
static int t_vni;
static int length;

#define CMD_LINE_OPT_ADD_MACHINE	"addmachine"
#define CMD_LINE_OPT_DEL_MACHINE	"delmachine"
#define CMD_LINE_OPT_GET_MACHINE	"getmachines"
#define CMD_LINE_OPT_VNI			"vni"
#define CMD_LINE_OPT_T_VNI			"t_vni"
#define CMD_LINE_OPT_PRIMARY_IPV4	"ipv4"
#define CMD_LINE_OPT_PRIMARY_IPV6	"ipv6"
#define CMD_LINE_OPT_ADD_ROUTE		"addroute"
#define CMD_LINE_OPT_DEL_ROUTE		"delroute"
#define CMD_LINE_OPT_GET_ROUTE		"listroutes"
#define CMD_LINE_OPT_T_PRIMARY_IPV6	"t_ipv6"
#define CMD_LINE_OPT_LENGTH			"length"
#define CMD_LINE_OPT_ADD_VIP		"addvip"
#define CMD_LINE_OPT_DEL_VIP		"delvip"
#define CMD_LINE_OPT_GET_VIP		"getvip"
#define CMD_LINE_OPT_PXE_IP			"pxe_ip"
#define CMD_LINE_OPT_BACK_IP		"back_ip"
#define CMD_LINE_OPT_PXE_STR		"pxe_str"
#define CMD_LINE_OPT_ADD_LB_VIP		"addlbvip"
#define CMD_LINE_OPT_DEL_LB_VIP		"dellbvip"

enum {
	CMD_LINE_OPT_MIN_NUM = 256,
	CMD_LINE_OPT_ADD_MACHINE_NUM,
	CMD_LINE_OPT_DEL_MACHINE_NUM,
	CMD_LINE_OPT_GET_MACHINE_NUM,
	CMD_LINE_OPT_ADD_ROUTE_NUM,
	CMD_LINE_OPT_DEL_ROUTE_NUM,
	CMD_LINE_OPT_GET_ROUTE_NUM,
	CMD_LINE_OPT_VNI_NUM,
	CMD_LINE_OPT_T_VNI_NUM,
	CMD_LINE_OPT_PRIMARY_IPV4_NUM,
	CMD_LINE_OPT_PRIMARY_IPV6_NUM,
	CMD_LINE_OPT_T_PRIMARY_IPV6_NUM,
	CMD_LINE_OPT_LENGTH_NUM,
	CMD_LINE_OPT_ADD_VIP_NUM,
	CMD_LINE_OPT_DEL_VIP_NUM,
	CMD_LINE_OPT_GET_VIP_NUM,
	CMD_LINE_OPT_PXE_IP_NUM,
	CMD_LINE_OPT_PXE_STR_NUM,
	CMD_LINE_OPT_BACK_IP_NUM,
	CMD_LINE_OPT_ADD_LB_VIP_NUM,
	CMD_LINE_OPT_DEL_LB_VIP_NUM,
};

static const struct option lgopts[] = {
	{CMD_LINE_OPT_ADD_MACHINE, 1, 0, CMD_LINE_OPT_ADD_MACHINE_NUM},
	{CMD_LINE_OPT_DEL_MACHINE, 1, 0, CMD_LINE_OPT_DEL_MACHINE_NUM},
	{CMD_LINE_OPT_GET_MACHINE, 0, 0, CMD_LINE_OPT_GET_MACHINE_NUM},
	{CMD_LINE_OPT_ADD_ROUTE, 0, 0, CMD_LINE_OPT_ADD_ROUTE_NUM},
	{CMD_LINE_OPT_DEL_ROUTE, 0, 0, CMD_LINE_OPT_DEL_ROUTE_NUM},
	{CMD_LINE_OPT_GET_ROUTE, 0, 0, CMD_LINE_OPT_GET_ROUTE_NUM},
	{CMD_LINE_OPT_VNI, 1, 0, CMD_LINE_OPT_VNI_NUM},
	{CMD_LINE_OPT_T_VNI, 1, 0, CMD_LINE_OPT_T_VNI_NUM},
	{CMD_LINE_OPT_PRIMARY_IPV4, 1, 0, CMD_LINE_OPT_PRIMARY_IPV4_NUM},
	{CMD_LINE_OPT_PRIMARY_IPV6, 1, 0, CMD_LINE_OPT_PRIMARY_IPV6_NUM},
	{CMD_LINE_OPT_T_PRIMARY_IPV6, 1, 0, CMD_LINE_OPT_T_PRIMARY_IPV6_NUM},
	{CMD_LINE_OPT_LENGTH, 1, 0, CMD_LINE_OPT_LENGTH_NUM},
	{CMD_LINE_OPT_ADD_VIP, 1, 0, CMD_LINE_OPT_ADD_VIP_NUM},
	{CMD_LINE_OPT_DEL_VIP, 1, 0, CMD_LINE_OPT_DEL_VIP_NUM},
	{CMD_LINE_OPT_GET_VIP, 1, 0, CMD_LINE_OPT_GET_VIP_NUM},
	{CMD_LINE_OPT_PXE_IP, 1, 0, CMD_LINE_OPT_PXE_IP_NUM},
	{CMD_LINE_OPT_PXE_STR, 1, 0, CMD_LINE_OPT_PXE_STR_NUM},
	{CMD_LINE_OPT_BACK_IP, 1, 0, CMD_LINE_OPT_BACK_IP_NUM},
	{CMD_LINE_OPT_ADD_LB_VIP, 0, 0, CMD_LINE_OPT_ADD_LB_VIP_NUM},
	{CMD_LINE_OPT_DEL_LB_VIP, 0, 0, CMD_LINE_OPT_DEL_LB_VIP_NUM},
	{NULL, 0, 0, 0},
};

/* Display usage */
static void dp_print_usage(const char *prgname)
{
	fprintf(stderr,
		"%s --"
		" -d"
		" [-D]"
		"\n",
		prgname);
}

int parse_args(int argc, char **argv)
{
	char *prgname = argv[0];
	int option_index;
	char **argvopt;
	int opt, ret;

	argvopt = argv;

	/* Error or normal output strings. */
	while ((opt = getopt_long(argc, argvopt, short_options, lgopts,
				  &option_index)) != EOF) {

		switch (opt) {
		case 'd':
		/* Intended fallthrough */
		case 'D':
			debug_mode = 1;
			break;

		/* Long options */
		case CMD_LINE_OPT_ADD_MACHINE_NUM:
			command = DP_CMD_ADD_MACHINE;
			strncpy(machine_str, optarg, 29);
			break;
		case CMD_LINE_OPT_DEL_MACHINE_NUM:
			command = DP_CMD_DEL_MACHINE;
			strncpy(machine_str, optarg, 29);
			break;
		case CMD_LINE_OPT_GET_MACHINE_NUM:
			command = DP_CMD_GET_MACHINE;
			break;
		case CMD_LINE_OPT_ADD_ROUTE_NUM:
			command = DP_CMD_ADD_ROUTE;
			break;
		case CMD_LINE_OPT_DEL_ROUTE_NUM:
			command = DP_CMD_DEL_ROUTE;
			break;
		case CMD_LINE_OPT_GET_ROUTE_NUM:
			command = DP_CMD_GET_ROUTE;
			break;
		case CMD_LINE_OPT_VNI_NUM:
			strncpy(vni_str, optarg, 29);
			vni = atoi(vni_str);
			break;
		case CMD_LINE_OPT_T_VNI_NUM:
			strncpy(t_vni_str, optarg, 29);
			t_vni = atoi(t_vni_str);
			break;
		case CMD_LINE_OPT_PRIMARY_IPV4_NUM:
			strncpy(ip_str, optarg, 29);
			version = dpdkonmetal::IPVersion::IPv4;
			break;
		case CMD_LINE_OPT_PRIMARY_IPV6_NUM:
			strncpy(ip6_str, optarg, 39);
			version = dpdkonmetal::IPVersion::IPv6;
			break;
		case CMD_LINE_OPT_T_PRIMARY_IPV6_NUM:
			strncpy(t_ip6_str, optarg, 39);
			break;
		case CMD_LINE_OPT_LENGTH_NUM:
			strncpy(len_str, optarg, 29);
			length = atoi(len_str);
			break;
		case CMD_LINE_OPT_ADD_VIP_NUM:
			command = DP_CMD_ADD_VIP;
			strncpy(machine_str, optarg, 29);
			break;
		case CMD_LINE_OPT_DEL_VIP_NUM:
			command = DP_CMD_DEL_VIP;
			strncpy(machine_str, optarg, 29);
			break;
		case CMD_LINE_OPT_GET_VIP_NUM:
			command = DP_CMD_GET_VIP;
			strncpy(machine_str, optarg, 29);
			break;
		case CMD_LINE_OPT_PXE_IP_NUM:
			strncpy(pxe_ip_str, optarg, 29);
			break;
		case CMD_LINE_OPT_PXE_STR_NUM:
			strncpy(pxe_path_str, optarg, 29);
			break;
		case CMD_LINE_OPT_BACK_IP_NUM:
			strncpy(back_ip_str, optarg, 29);
			break;
		case CMD_LINE_OPT_ADD_LB_VIP_NUM:
			command = DP_CMD_ADD_LB_VIP;
			break;
		case CMD_LINE_OPT_DEL_LB_VIP_NUM:
			command = DP_CMD_DEL_LB_VIP;
			break;
		default:
			dp_print_usage(prgname);
			return -1;
		}
	}

	if (optind >= 0)
		argv[optind - 1] = prgname;
	ret = optind - 1;
	optind = 1; /* Reset getopt lib */

	return ret;
}

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
	void AddMachine() {
			AddMachineRequest request;
			AddMachineResponse response;
			ClientContext context;
			IPConfig *ip_config = new IPConfig();
			PXEConfig *pxe_config = new PXEConfig();
			IPConfig *ipv6_config = new IPConfig();

			ip_config->set_primaryaddress(ip_str);
			pxe_config->set_bootfilename(pxe_path_str);
			pxe_config->set_nextserver(pxe_ip_str);
			ip_config->set_allocated_pxeconfig(pxe_config);
			ipv6_config->set_primaryaddress(ip6_str);
			request.set_machineid(machine_str);
			request.set_vni(vni);
			request.set_allocated_ipv4config(ip_config);
			request.set_allocated_ipv6config(ipv6_config);
			request.set_machinetype(dpdkonmetal::MachineType::VirtualMachine);
			stub_->addMachine(&context, request, &response);
			if (!response.status().error())
				printf("Allocated VF for you %s \n", response.vf().name().c_str());
			else
				printf("Error detected with code %d\n", response.status().error());
	}

	void AddRoute() {
			VNIRouteMsg request;
			Status reply;
			ClientContext context;
			VNIMsg *vni_msg = new VNIMsg();
			Route *route = new Route();
			Prefix *prefix = new Prefix();

			vni_msg->set_vni(vni);
			prefix->set_ipversion(version);
			if(version == dpdkonmetal::IPVersion::IPv4) {
				prefix->set_address(ip_str);
			} else {
				prefix->set_address(ip6_str);
			}
			prefix->set_prefixlength(length);
			route->set_allocated_prefix(prefix);
			route->set_ipversion(dpdkonmetal::IPVersion::IPv6);
			route->set_nexthopvni(t_vni);
			route->set_weight(100);
			route->set_nexthopaddress(t_ip6_str);
			request.set_allocated_route(route);
			request.set_allocated_vni(vni_msg);
			stub_->addRoute(&context, request, &reply);
			if (reply.error()) {
				printf("Received an error %d \n", reply.error());
			}
	}

	void DelRoute() {
			VNIRouteMsg request;
			Status reply;
			ClientContext context;
			VNIMsg *vni_msg = new VNIMsg();
			Route *route = new Route();
			Prefix *prefix = new Prefix();

			vni_msg->set_vni(vni);
			prefix->set_ipversion(version);
			if(version == dpdkonmetal::IPVersion::IPv4) {
				prefix->set_address(ip_str);
			} else {
				prefix->set_address(ip6_str);
			}
			prefix->set_prefixlength(length);
			route->set_allocated_prefix(prefix);
			route->set_ipversion(dpdkonmetal::IPVersion::IPv6);
			route->set_nexthopvni(t_vni);
			route->set_weight(100);
			route->set_nexthopaddress(t_ip6_str);
			request.set_allocated_route(route);
			request.set_allocated_vni(vni_msg);
			stub_->deleteRoute(&context, request, &reply);
			if (reply.error()) {
				printf("Received an error %d \n", reply.error());
			}
	}

	void ListRoutes() {
			VNIMsg request;
			RoutesMsg reply;
			ClientContext context;
			int i;

			request.set_vni(vni);

			stub_->listRoutes(&context, request, &reply);
			for (i = 0; i < reply.routes_size(); i++)
			{
				printf("Route prefix %s len %d target vni %d target ipv6 %s\n",
					reply.routes(i).prefix().address().c_str(),
					reply.routes(i).prefix().prefixlength(), 
					reply.routes(i).nexthopvni(),
					reply.routes(i).nexthopaddress().c_str());
			}
	}

	void AddLBVIP() {
			LBMsg request;
			Status reply;
			ClientContext context;
			LBIP *vip_ip = new LBIP();
			LBIP *back_ip = new LBIP();

			request.set_vni(vni);
			vip_ip->set_ipversion(version);
			if(version == dpdkonmetal::IPVersion::IPv4)
				vip_ip->set_address(ip_str);
			request.set_allocated_lbvipip(vip_ip);

			if(version == dpdkonmetal::IPVersion::IPv4)
				back_ip->set_address(back_ip_str);
			request.set_allocated_lbbackendip(back_ip);
			stub_->addLBVIP(&context, request, &reply);
			if (reply.error()) {
				printf("Received an error %d \n", reply.error());
			}
	}

	void DelLBVIP() {
			LBMsg request;
			Status reply;
			ClientContext context;
			LBIP *vip_ip = new LBIP();
			LBIP *back_ip = new LBIP();

			request.set_vni(vni);
			vip_ip->set_ipversion(version);
			if(version == dpdkonmetal::IPVersion::IPv4)
				vip_ip->set_address(ip_str);
			request.set_allocated_lbvipip(vip_ip);

			if(version == dpdkonmetal::IPVersion::IPv4)
				back_ip->set_address(back_ip_str);
			request.set_allocated_lbbackendip(back_ip);
			stub_->delLBVIP(&context, request, &reply);
			if (reply.error()) {
				printf("Received an error %d \n", reply.error());
			}
	}

	void AddVIP() {
			MachineVIPMsg request;
			Status reply;
			ClientContext context;
			MachineVIPIP *vip_ip = new MachineVIPIP();

			request.set_machineid(machine_str);
			vip_ip->set_ipversion(version);
			if(version == dpdkonmetal::IPVersion::IPv4)
				vip_ip->set_address(ip_str);
			request.set_allocated_machinevipip(vip_ip);
			stub_->addMachineVIP(&context, request, &reply);
			if (reply.error()) {
				printf("Received an error %d \n", reply.error());
			}
	}

	void DelVIP() {
			MachineIDMsg request;
			Status reply;
			ClientContext context;

			request.set_machineid(machine_str);
			stub_->delMachineVIP(&context, request, &reply);
			if (reply.error()) {
				printf("Received an error %d \n", reply.error());
			}
	}

	void GetVIP() {
			MachineIDMsg request;
			MachineVIPIP reply;
			ClientContext context;

			request.set_machineid(machine_str);
			stub_->getMachineVIP(&context, request, &reply);
			if (!reply.status().error())
				printf("Received VIP %s \n", reply.address().c_str());
			else
				printf("Error detected with code %d\n", reply.status().error());
			
	}

	void DelMachine() {
			MachineIDMsg request;
			Status reply;
			ClientContext context;

			request.set_machineid(machine_str);
			stub_->deleteMachine(&context, request, &reply);
			if (reply.error()) {
				printf("Received an error %d \n", reply.error());
			}
	}

	void GetMachines() {
			Empty request;
			MachinesMsg reply;
			ClientContext context;
			int i;

			stub_->listMachines(&context, request, &reply);
			for (i = 0; i < reply.machines_size(); i++)
			{
				printf("Machine %s ipv4 %s ipv6 %s vni %d\n", reply.machines(i).machineid().c_str(),
					reply.machines(i).primaryipv4address().c_str(), 
					reply.machines(i).primaryipv6address().c_str(),
					reply.machines(i).vni());
			}
	}

private:
	std::unique_ptr<DPDKonmetal::Stub> stub_;
};

int main(int argc, char** argv)
{
	GRPCClient dpdk_client(grpc::CreateChannel("localhost:1337", grpc::InsecureChannelCredentials()));

	parse_args(argc, argv);

	switch (command)
	{
	case DP_CMD_ADD_MACHINE:
		dpdk_client.AddMachine();
		std::cout << "Addmachine called " << std::endl;
		printf("IP %s, IPv6 %s PXE Server IP %s PXE Path %s\n", ip_str, ip6_str, pxe_ip_str, pxe_path_str);
		break;
	case DP_CMD_DEL_MACHINE:
		dpdk_client.DelMachine();
		std::cout << "Delmachine called " << std::endl;
		break;
	case DP_CMD_GET_MACHINE:
		std::cout << "Getmachine called " << std::endl;
		dpdk_client.GetMachines();
		break;
	case DP_CMD_ADD_ROUTE:
		dpdk_client.AddRoute();
		std::cout << "Addroute called " << std::endl;
		printf("Route ip %s length %d vni %d target ipv6 %s target vni %d\n", ip_str, length, vni, ip6_str, t_vni);
		break;
	case DP_CMD_GET_ROUTE:
		std::cout << "Listroute called " << std::endl;
		dpdk_client.ListRoutes();
		break;
	case DP_CMD_DEL_ROUTE:
		dpdk_client.DelRoute();
		std::cout << "Delroute called " << std::endl;
		break;
	case DP_CMD_ADD_VIP:
		dpdk_client.AddVIP();
		std::cout << "Addvip called " << std::endl;
		break;
	case DP_CMD_DEL_VIP:
		dpdk_client.DelVIP();
		std::cout << "Delvip called " << std::endl;
		break;
	case DP_CMD_GET_VIP:
		std::cout << "Getvip called " << std::endl;
		dpdk_client.GetVIP();
		break;
	case DP_CMD_ADD_LB_VIP:
		dpdk_client.AddLBVIP();
		std::cout << "Addlbvip called " << std::endl;
		break;
	case DP_CMD_DEL_LB_VIP:
		dpdk_client.DelLBVIP();
		std::cout << "Dellbvip called " << std::endl;
		break;
	default:
		break;
	}

	return 0;
}
