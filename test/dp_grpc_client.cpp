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
using dpdkonmetal::DPDKonmetal;
using dpdkonmetal::Status;
using dpdkonmetal::Empty;
using dpdkonmetal::AddMachineResponse;
using dpdkonmetal::AddMachineRequest;
using dpdkonmetal::IPConfig;
using dpdkonmetal::VNIRouteMsg;
using dpdkonmetal::VNIMsg;
using dpdkonmetal::Route;
using dpdkonmetal::Prefix;
using dpdkonmetal::IPVersion;

static const char short_options[] = "d" /* debug */
				    "D"	 /* promiscuous */;

typedef enum {
	DP_CMD_NONE,
	DP_CMD_ADD_MACHINE,
	DP_CMD_ADD_ROUTE,
} cmd_type;

static char ip6_str[40] = {0};
static char t_ip6_str[40] = {0};
static char vni_str[30] = {0};
static char len_str[30] = {0};
static char t_vni_str[30] = {0};
static char machine_str[30] = {0};
static char route_str[30] = {0};
static char ip_str[30] = {0};

static int command;
static int debug_mode;
static int vni;
static int t_vni;
static int length;

#define CMD_LINE_OPT_ADD_MACHINE	"addmachine"
#define CMD_LINE_OPT_VNI			"vni"
#define CMD_LINE_OPT_T_VNI			"t_vni"
#define CMD_LINE_OPT_PRIMARY_IPV4	"ipv4"
#define CMD_LINE_OPT_PRIMARY_IPV6	"ipv6"
#define CMD_LINE_OPT_ADD_ROUTE		"addroute"
#define CMD_LINE_OPT_T_PRIMARY_IPV6	"t_ipv6"
#define CMD_LINE_OPT_LENGTH			"length"

enum {
	CMD_LINE_OPT_MIN_NUM = 256,
	CMD_LINE_OPT_ADD_MACHINE_NUM,
	CMD_LINE_OPT_ADD_ROUTE_NUM,
	CMD_LINE_OPT_VNI_NUM,
	CMD_LINE_OPT_T_VNI_NUM,
	CMD_LINE_OPT_PRIMARY_IPV4_NUM,
	CMD_LINE_OPT_PRIMARY_IPV6_NUM,
	CMD_LINE_OPT_T_PRIMARY_IPV6_NUM,
	CMD_LINE_OPT_LENGTH_NUM,
};

static const struct option lgopts[] = {
	{CMD_LINE_OPT_ADD_MACHINE, 1, 0, CMD_LINE_OPT_ADD_MACHINE_NUM},
	{CMD_LINE_OPT_ADD_ROUTE, 1, 0, CMD_LINE_OPT_ADD_ROUTE_NUM},
	{CMD_LINE_OPT_VNI, 1, 0, CMD_LINE_OPT_VNI_NUM},
	{CMD_LINE_OPT_T_VNI, 1, 0, CMD_LINE_OPT_T_VNI_NUM},
	{CMD_LINE_OPT_PRIMARY_IPV4, 1, 0, CMD_LINE_OPT_PRIMARY_IPV4_NUM},
	{CMD_LINE_OPT_PRIMARY_IPV6, 1, 0, CMD_LINE_OPT_PRIMARY_IPV6_NUM},
	{CMD_LINE_OPT_T_PRIMARY_IPV6, 1, 0, CMD_LINE_OPT_T_PRIMARY_IPV6_NUM},
	{CMD_LINE_OPT_LENGTH, 1, 0, CMD_LINE_OPT_LENGTH_NUM},
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

		case CMD_LINE_OPT_ADD_ROUTE_NUM:
			command = DP_CMD_ADD_ROUTE;
			strncpy(route_str, optarg, 29);
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
			break;
		case CMD_LINE_OPT_PRIMARY_IPV6_NUM:
			strncpy(ip6_str, optarg, 39);
			break;
		case CMD_LINE_OPT_T_PRIMARY_IPV6_NUM:
			strncpy(t_ip6_str, optarg, 39);
			break;
		case CMD_LINE_OPT_LENGTH_NUM:
			strncpy(len_str, optarg, 29);
			length = atoi(len_str);
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
			IPConfig *ipv6_config = new IPConfig();

			ip_config->set_primaryaddress(ip_str);
			ipv6_config->set_primaryaddress(ip6_str);
			request.set_machineid(machine_str);
			request.set_vni(vni);
			request.set_allocated_ipv4config(ip_config);
			request.set_allocated_ipv6config(ipv6_config);
			request.set_machinetype(dpdkonmetal::MachineType::VirtualMachine);
			stub_->addMachine(&context, request, &response);
	}

	void AddRoute() {
			VNIRouteMsg request;
			Status reply;
			ClientContext context;
			VNIMsg *vni_msg = new VNIMsg();
			Route *route = new Route();
			Prefix *prefix = new Prefix();

			vni_msg->set_vni(vni);

			prefix->set_ipversion(dpdkonmetal::IPVersion::IPv4);
			prefix->set_address(ip_str);
			prefix->set_prefixlength(length);
			route->set_allocated_prefix(prefix);
			route->set_ipversion(dpdkonmetal::IPVersion::IPv6);
			route->set_nexthopvni(t_vni);
			route->set_weight(100);
			route->set_nexthopaddress(ip6_str);
			request.set_allocated_route(route);
			request.set_allocated_vni(vni_msg);
			stub_->addRoute(&context, request, &reply);
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
		printf("IP %s, IPv6 %s\n", ip_str,ip6_str);
		break;
	case DP_CMD_ADD_ROUTE:
		dpdk_client.AddRoute();
		std::cout << "Addroute called " << std::endl;
		printf("Route ip %s length %d vni %d target ipv6 %s target vni %d\n", ip_str, length, vni, ip6_str, t_vni);
		break;
	default:
		break;
	}

	return 0;
}
