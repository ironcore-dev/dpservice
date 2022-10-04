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
using namespace std::chrono;

static const char short_options[] = "d" /* debug */
				    "D"	 /* promiscuous */;

#define DP_MAX_LB_PORTS 16

typedef enum {
	DP_CMD_NONE,
	DP_CMD_ADD_MACHINE,
	DP_CMD_DEL_MACHINE,
	DP_CMD_GET_MACHINE,
	DP_CMD_LIST_MACHINES,
	DP_CMD_ADD_ROUTE,
	DP_CMD_DEL_ROUTE,
	DP_CMD_GET_ROUTE,
	DP_CMD_ADD_VIP,
	DP_CMD_DEL_VIP,
	DP_CMD_GET_VIP,
	DP_CMD_ADD_LB_VIP,
	DP_CMD_DEL_LB_VIP,
	DP_CMD_LIST_LB_VIP,
	DP_CMD_ADD_PFX,
	DP_CMD_LIST_PFX,
	DP_CMD_DEL_PFX,
	DP_CMD_INITIALIZED,
	DP_CMD_INIT,
	DP_CMD_CREATE_LB,
	DP_CMD_DEL_LB,
	DP_CMD_GET_LB,
} cmd_type;

static char ip6_str[40] = {0};
static char t_ip6_str[40] = {0};
static char vni_str[30] = {0};
static char len_str[30] = {0};
static char t_vni_str[30] = {0};
static char machine_str[64] = {0};
static char lb_id_str[64] = {0};
static char ip_str[30] = {0};
static char back_ip_str[30] = {0};
static char pxe_ip_str[30] = {0};
static char vm_pci_str[30] = {0};
static char pxe_path_str[30] = {0};
static char port_str[30] = {0};
static char proto_str[30] = {0};
static IPVersion version;

static int command;
static int debug_mode;
static int vni;
static int t_vni;
static int length;
static bool pfx_lb_enabled = false;

#define CMD_LINE_OPT_INIT			"init"
#define CMD_LINE_OPT_INITIALIZED	"is_initialized"
#define CMD_LINE_OPT_PCI			"vm_pci"
#define CMD_LINE_OPT_ADD_PFX		"addpfx"
#define CMD_LINE_OPT_LIST_PFX		"listpfx"
#define CMD_LINE_OPT_DEL_PFX		"delpfx"
#define CMD_LINE_OPT_ADD_MACHINE	"addmachine"
#define CMD_LINE_OPT_DEL_MACHINE	"delmachine"
#define CMD_LINE_OPT_GET_MACHINE	"getmachine"
#define CMD_LINE_OPT_LIST_MACHINES	"getmachines"
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
#define CMD_LINE_OPT_PORT_STR		"port"
#define CMD_LINE_OPT_PROTO_STR		"protocol"
#define CMD_LINE_OPT_ADD_LB_VIP		"addlbvip"
#define CMD_LINE_OPT_DEL_LB_VIP		"dellbvip"
#define CMD_LINE_OPT_LIST_LB_VIP	"listbackips"
#define CMD_LINE_OPT_CREATE_LB		"createlb"
#define CMD_LINE_OPT_DEL_LB			"dellb"
#define CMD_LINE_OPT_GET_LB			"getlb"
#define CMD_LINE_OPT_PFX_LB			"lb_pfx"

enum {
	CMD_LINE_OPT_MIN_NUM = 256,
	CMD_LINE_OPT_ADD_MACHINE_NUM,
	CMD_LINE_OPT_DEL_MACHINE_NUM,
	CMD_LINE_OPT_GET_MACHINE_NUM,
	CMD_LINE_OPT_LIST_MACHINES_NUM,
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
	CMD_LINE_OPT_PORT_NUM,
	CMD_LINE_OPT_PROTO_NUM,
	CMD_LINE_OPT_PXE_STR_NUM,
	CMD_LINE_OPT_PCI_NUM,
	CMD_LINE_OPT_BACK_IP_NUM,
	CMD_LINE_OPT_ADD_LB_VIP_NUM,
	CMD_LINE_OPT_DEL_LB_VIP_NUM,
	CMD_LINE_OPT_LIST_LB_VIP_NUM,
	CMD_LINE_OPT_ADD_PFX_NUM,
	CMD_LINE_OPT_LIST_PFX_NUM,
	CMD_LINE_OPT_DEL_PFX_NUM,
	CMD_LINE_OPT_INITIALIZED_NUM,
	CMD_LINE_OPT_INIT_NUM,
	CMD_LINE_OPT_CREATE_LB_NUM,
	CMD_LINE_OPT_DEL_LB_NUM,
	CMD_LINE_OPT_GET_LB_NUM,
	CMD_LINE_OPT_PFX_LB_NUM,
};

static const struct option lgopts[] = {
	{CMD_LINE_OPT_ADD_MACHINE, 1, 0, CMD_LINE_OPT_ADD_MACHINE_NUM},
	{CMD_LINE_OPT_DEL_MACHINE, 1, 0, CMD_LINE_OPT_DEL_MACHINE_NUM},
	{CMD_LINE_OPT_GET_MACHINE, 1, 0, CMD_LINE_OPT_GET_MACHINE_NUM},
	{CMD_LINE_OPT_LIST_MACHINES, 0, 0, CMD_LINE_OPT_LIST_MACHINES_NUM},
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
	{CMD_LINE_OPT_PORT_STR, 1, 0, CMD_LINE_OPT_PORT_NUM},
	{CMD_LINE_OPT_PROTO_STR, 1, 0, CMD_LINE_OPT_PROTO_NUM},
	{CMD_LINE_OPT_PXE_STR, 1, 0, CMD_LINE_OPT_PXE_STR_NUM},
	{CMD_LINE_OPT_PCI, 1, 0, CMD_LINE_OPT_PCI_NUM},
	{CMD_LINE_OPT_BACK_IP, 1, 0, CMD_LINE_OPT_BACK_IP_NUM},
	{CMD_LINE_OPT_ADD_LB_VIP, 1, 0, CMD_LINE_OPT_ADD_LB_VIP_NUM},
	{CMD_LINE_OPT_DEL_LB_VIP, 1, 0, CMD_LINE_OPT_DEL_LB_VIP_NUM},
	{CMD_LINE_OPT_LIST_LB_VIP, 1, 0, CMD_LINE_OPT_LIST_LB_VIP_NUM},
	{CMD_LINE_OPT_ADD_PFX, 1, 0, CMD_LINE_OPT_ADD_PFX_NUM},
	{CMD_LINE_OPT_LIST_PFX, 1, 0, CMD_LINE_OPT_LIST_PFX_NUM},
	{CMD_LINE_OPT_DEL_PFX, 1, 0, CMD_LINE_OPT_DEL_PFX_NUM},
	{CMD_LINE_OPT_INITIALIZED, 0, 0, CMD_LINE_OPT_INITIALIZED_NUM},
	{CMD_LINE_OPT_INIT, 0, 0, CMD_LINE_OPT_INIT_NUM},
	{CMD_LINE_OPT_CREATE_LB, 1, 0, CMD_LINE_OPT_CREATE_LB_NUM},
	{CMD_LINE_OPT_DEL_LB, 1, 0, CMD_LINE_OPT_DEL_LB_NUM},
	{CMD_LINE_OPT_GET_LB, 1, 0, CMD_LINE_OPT_GET_LB_NUM},
	{CMD_LINE_OPT_PFX_LB, 0, 0, CMD_LINE_OPT_PFX_LB_NUM},
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
			strncpy(machine_str, optarg, 63);
			break;
		case CMD_LINE_OPT_DEL_MACHINE_NUM:
			command = DP_CMD_DEL_MACHINE;
			strncpy(machine_str, optarg, 63);
			break;
		case CMD_LINE_OPT_GET_MACHINE_NUM:
			command = DP_CMD_GET_MACHINE;
			strncpy(machine_str, optarg, 63);
			break;
		case CMD_LINE_OPT_LIST_MACHINES_NUM:
			command = DP_CMD_LIST_MACHINES;
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
			strncpy(machine_str, optarg, 63);
			break;
		case CMD_LINE_OPT_ADD_PFX_NUM:
			command = DP_CMD_ADD_PFX;
			strncpy(machine_str, optarg, 63);
			break;
		case CMD_LINE_OPT_DEL_PFX_NUM:
			command = DP_CMD_DEL_PFX;
			strncpy(machine_str, optarg, 63);
			break;
		case CMD_LINE_OPT_LIST_PFX_NUM:
			command = DP_CMD_LIST_PFX;
			strncpy(machine_str, optarg, 63);
			break;
		case CMD_LINE_OPT_DEL_VIP_NUM:
			command = DP_CMD_DEL_VIP;
			strncpy(machine_str, optarg, 63);
			break;
		case CMD_LINE_OPT_GET_VIP_NUM:
			command = DP_CMD_GET_VIP;
			strncpy(machine_str, optarg, 63);
			break;
		case CMD_LINE_OPT_PXE_IP_NUM:
			strncpy(pxe_ip_str, optarg, 29);
			break;
		case CMD_LINE_OPT_PXE_STR_NUM:
			strncpy(pxe_path_str, optarg, 29);
			break;
		case CMD_LINE_OPT_PORT_NUM:
			strncpy(port_str, optarg, 29);
			break;
		case CMD_LINE_OPT_PROTO_NUM:
			strncpy(proto_str, optarg, 29);
			break;
		case CMD_LINE_OPT_PCI_NUM:
			strncpy(vm_pci_str, optarg, 29);
			break;
		case CMD_LINE_OPT_BACK_IP_NUM:
			strncpy(back_ip_str, optarg, 29);
			break;
		case CMD_LINE_OPT_ADD_LB_VIP_NUM:
			command = DP_CMD_ADD_LB_VIP;
			strncpy(lb_id_str, optarg, 63);
			break;
		case CMD_LINE_OPT_DEL_LB_VIP_NUM:
			command = DP_CMD_DEL_LB_VIP;
			strncpy(lb_id_str, optarg, 63);
			break;
		case CMD_LINE_OPT_LIST_LB_VIP_NUM:
			command = DP_CMD_LIST_LB_VIP;
			strncpy(lb_id_str, optarg, 63);
			break;
		case CMD_LINE_OPT_INITIALIZED_NUM:
			command = DP_CMD_INITIALIZED;
			break;
		case CMD_LINE_OPT_INIT_NUM:
			command = DP_CMD_INIT;
			break;
		case CMD_LINE_OPT_CREATE_LB_NUM:
			command = DP_CMD_CREATE_LB;
			strncpy(lb_id_str, optarg, 63);
			break;
		case CMD_LINE_OPT_DEL_LB_NUM:
			command = DP_CMD_DEL_LB;
			strncpy(lb_id_str, optarg, 63);
			break;
		case CMD_LINE_OPT_GET_LB_NUM:
			command = DP_CMD_GET_LB;
			strncpy(lb_id_str, optarg, 63);
			break;
		case CMD_LINE_OPT_PFX_LB_NUM:
			pfx_lb_enabled = true;
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
	void AddInterface() {
			CreateInterfaceRequest request;
			CreateInterfaceResponse response;
			ClientContext context;
			IPConfig *ip_config = new IPConfig();
			PXEConfig *pxe_config = new PXEConfig();
			IPConfig *ipv6_config = new IPConfig();

			ip_config->set_primaryaddress(ip_str);
			pxe_config->set_bootfilename(pxe_path_str);
			pxe_config->set_nextserver(pxe_ip_str);
			ip_config->set_allocated_pxeconfig(pxe_config);
			ipv6_config->set_primaryaddress(ip6_str);
			request.set_interfaceid(machine_str);
			request.set_vni(vni);
			request.set_allocated_ipv4config(ip_config);
			request.set_allocated_ipv6config(ipv6_config);
			request.set_interfacetype(dpdkonmetal::InterfaceType::VirtualInterface);
			if (vm_pci_str[0] != '\0')
				request.set_devicename(vm_pci_str);
			stub_->createInterface(&context, request, &response);
			if (!response.response().status().error()) {
				printf("Allocated VF for you %s \n", response.vf().name().c_str());
				printf("Received underlay route : %s \n", response.response().underlayroute().c_str());
			} else {
				printf("Received an error %d\n", response.response().status().error());
			}
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
			AddLoadBalancerTargetRequest request;
			Status reply;
			ClientContext context;
			LBIP *back_ip = new LBIP();


			request.set_loadbalancerid(lb_id_str);
			back_ip->set_ipversion(dpdkonmetal::IPVersion::IPv6);
			back_ip->set_address(t_ip6_str);
			request.set_allocated_targetip(back_ip);
			stub_->addLoadBalancerTarget(&context, request, &reply);
			if (reply.error()) {
				printf("Received an error %d \n", reply.error());
			} else {
				printf("LB target added \n");
			}
	}

	void DelLBVIP() {
			DeleteLoadBalancerTargetRequest request;
			Status reply;
			ClientContext context;
			LBIP *back_ip = new LBIP();

			request.set_loadbalancerid(lb_id_str);
			back_ip->set_ipversion(dpdkonmetal::IPVersion::IPv6);
			back_ip->set_address(t_ip6_str);
			request.set_allocated_targetip(back_ip);
			stub_->deleteLoadBalancerTarget(&context, request, &reply);
			if (reply.error()) {
				printf("Received an error %d \n", reply.error());
			}
	}

	void ListBackIPs() {
			GetLoadBalancerTargetsRequest request;
			GetLoadBalancerTargetsResponse reply;
			ClientContext context;
			int i;

			request.set_loadbalancerid(lb_id_str);

			stub_->getLoadBalancerTargets(&context, request, &reply);
			for (i = 0; i < reply.targetips_size(); i++)
			{
				printf("Backend ip %s \n",
					reply.targetips(i).address().c_str());
			}
	}

	void AddVIP() {
			InterfaceVIPMsg request;
			IpAdditionResponse reply;
			ClientContext context;
			InterfaceVIPIP *vip_ip = new InterfaceVIPIP();

			request.set_interfaceid(machine_str);
			vip_ip->set_ipversion(version);
			if(version == dpdkonmetal::IPVersion::IPv4)
				vip_ip->set_address(ip_str);
			request.set_allocated_interfacevipip(vip_ip);
			stub_->addInterfaceVIP(&context, request, &reply);
			if (reply.status().error()) {
				printf("Received an error %d \n", reply.status().error());
			} else {
				printf("Received underlay route : %s \n", reply.underlayroute().c_str());
			}
	}

	void AddPfx() {
			InterfacePrefixMsg request;
			IpAdditionResponse reply;
			ClientContext context;
			Prefix *pfx_ip = new Prefix();
			InterfaceIDMsg *m_id = new InterfaceIDMsg();

			m_id->set_interfaceid(machine_str);
			request.set_allocated_interfaceid(m_id);
			pfx_ip->set_ipversion(version);
			if(version == dpdkonmetal::IPVersion::IPv4)
				pfx_ip->set_address(ip_str);
			pfx_ip->set_prefixlength(length);
			pfx_ip->set_loadbalancerenabled(pfx_lb_enabled);
			request.set_allocated_prefix(pfx_ip);
			stub_->addInterfacePrefix(&context, request, &reply);
			if (reply.status().error()) {
				printf("Received an error %d \n", reply.status().error());
			} else {
				printf("Received underlay route : %s \n", reply.underlayroute().c_str());
			}
	}

	void CreateLB() {
			CreateLoadBalancerRequest request;
			CreateLoadBalancerResponse reply;
			ClientContext context;
			LBIP *lb_ip = new LBIP(); 
			LBPort *lb_port;
			uint16_t ports[DP_MAX_LB_PORTS];
			uint16_t countpro = 0, countp = 0, i;
			uint16_t final_count = 0;
			char protos[DP_MAX_LB_PORTS][4];
			char *pt;

			request.set_loadbalancerid(lb_id_str);
			request.set_vni(vni);
			lb_ip->set_ipversion(dpdkonmetal::IPVersion::IPv4);
			lb_ip->set_address(ip_str);
			request.set_allocated_lbvipip(lb_ip);

			pt = strtok(port_str,",");
			while (pt != NULL) {
				if (countp == DP_MAX_LB_PORTS)
					break;
				ports[countp++] = atoi(pt);
				pt = strtok(NULL, ",");
			}

			pt = strtok(proto_str,",");
			while (pt != NULL) {
				if (countpro == DP_MAX_LB_PORTS)
					break;
				snprintf(&protos[countpro++][0], 4, "%s", pt);
				pt = strtok (NULL, ",");
			}
			final_count = countpro > countp ? countp : countpro;
			for (i = 0; i < final_count; i++) {
				lb_port = request.add_lbports();
				lb_port->set_port(ports[i]);
				if (strncasecmp("tcp", &protos[i][0], 29) == 0)
					lb_port->set_protocol(dpdkonmetal::Protocol::TCP);
				if (strncasecmp("udp", &protos[i][0], 29) == 0)
					lb_port->set_protocol(dpdkonmetal::Protocol::UDP);
			}

			stub_->createLoadBalancer(&context, request, &reply);
			if (reply.status().error()) {
				printf("Received an error %d \n", reply.status().error());
			} else {
				printf("Received underlay route : %s \n", reply.underlayroute().c_str());
			}
	}

	void GetLB() {
			GetLoadBalancerRequest request;
			GetLoadBalancerResponse reply;
			ClientContext context;
			int i;

			request.set_loadbalancerid(lb_id_str);

			stub_->getLoadBalancer(&context, request, &reply);
			if (reply.status().error()) {
				printf("Received an error %d \n", reply.status().error());
			} else {
				printf("Received LB with vni: %d LB ip: %s with ports: ", reply.vni(), reply.lbvipip().address().c_str());
				for (i = 0; i < reply.lbports_size(); i++) {
					if (reply.lbports(i).protocol() == TCP)
						printf("%d,%s ", reply.lbports(i).port(), "tcp");
					if (reply.lbports(i).protocol() == UDP)
						printf("%d,%s ", reply.lbports(i).port(), "udp");
				}
				printf("\n");
			}
	}

	void DelLB() {
			DeleteLoadBalancerRequest request;
			ClientContext context;
			Status reply;

			request.set_loadbalancerid(lb_id_str);

			stub_->deleteLoadBalancer(&context, request, &reply);
			if (reply.error()) {
				printf("Received an error %d \n", reply.error());
			} else {
				printf("Delete LB Success");
			}
	}

	void Initialized() {
			Empty request;
			UUIDMsg reply;
			ClientContext context;
			system_clock::time_point deadline = system_clock::now() + seconds(5);

			context.set_deadline(deadline);
			reply.set_uuid("");

			grpc::Status ret = stub_->initialized(&context, request, &reply);
			/* Aborted answers mean that dp-service is not initialized with init() call yet */
			/* So do not exit with error in that case */
			if ((reply.uuid().c_str()[0] == '\0') && (ret.error_code() != grpc::StatusCode::ABORTED))
				exit(1);
			printf("Received UUID %s \n", reply.uuid().c_str());
	}

	void Init() {
			InitConfig request;
			Status reply;
			ClientContext context;
			system_clock::time_point deadline = system_clock::now() + seconds(5);

			context.set_deadline(deadline);

			stub_->init(&context, request, &reply);
	}

	void DelPfx() {
			InterfacePrefixMsg request;
			Status reply;
			ClientContext context;
			Prefix *pfx_ip = new Prefix();
			InterfaceIDMsg *m_id = new InterfaceIDMsg();

			m_id->set_interfaceid(machine_str);
			request.set_allocated_interfaceid(m_id);
			pfx_ip->set_ipversion(version);
			if(version == dpdkonmetal::IPVersion::IPv4)
				pfx_ip->set_address(ip_str);
			pfx_ip->set_prefixlength(length);
			request.set_allocated_prefix(pfx_ip);
			stub_->deleteInterfacePrefix(&context, request, &reply);
			if (reply.error()) {
				printf("Received an error %d \n", reply.error());
			}
	}

	void ListPfx() {
			InterfaceIDMsg request;
			PrefixesMsg reply;
			ClientContext context;
			int i;

			request.set_interfaceid(machine_str);
			stub_->listInterfacePrefixes(&context, request, &reply);
			for (i = 0; i < reply.prefixes_size(); i++) {
				printf("Route prefix %s len %d \n",
					reply.prefixes(i).address().c_str(),
					reply.prefixes(i).prefixlength());
			}
	}

	void DelVIP() {
			InterfaceIDMsg request;
			Status reply;
			ClientContext context;

			request.set_interfaceid(machine_str);
			stub_->deleteInterfaceVIP(&context, request, &reply);
			if (reply.error()) {
				printf("Received an error %d \n", reply.error());
			}
	}

	void GetVIP() {
			InterfaceIDMsg request;
			InterfaceVIPIP reply;
			ClientContext context;

			request.set_interfaceid(machine_str);
			stub_->getInterfaceVIP(&context, request, &reply);
			if (!reply.status().error())
				printf("Received VIP %s \n", reply.address().c_str());
			else
				printf("Error detected with code %d\n", reply.status().error());
			
	}

	void DelInterface() {
			InterfaceIDMsg request;
			Status reply;
			ClientContext context;

			request.set_interfaceid(machine_str);
			stub_->deleteInterface(&context, request, &reply);
			if (reply.error()) {
				printf("Received an error %d \n", reply.error());
			}
	}

	void GetInterface() {
			InterfaceIDMsg request;
			GetInterfaceResponse reply;
			ClientContext context;

			request.set_interfaceid(machine_str);
			stub_->getInterface(&context, request, &reply);
			if (reply.status().error()) {
				printf("Received an error %d \n", reply.status().error());
			} else {
				printf("Interface with ipv4 %s ipv6 %s vni %d pci %s underlayroute %s\n",
				reply.interface().primaryipv4address().c_str(), 
				reply.interface().primaryipv6address().c_str(),
				reply.interface().vni(),
				reply.interface().pcidpname().c_str(),
				reply.interface().underlayroute().c_str());
			}
	}

	void GetInterfaces() {
			Empty request;
			InterfacesMsg reply;
			ClientContext context;
			int i;

			stub_->listInterfaces(&context, request, &reply);
			for (i = 0; i < reply.interfaces_size(); i++)
			{
				printf("Interface %s ipv4 %s ipv6 %s vni %d pci %s underlayroute %s\n", reply.interfaces(i).interfaceid().c_str(),
					reply.interfaces(i).primaryipv4address().c_str(), 
					reply.interfaces(i).primaryipv6address().c_str(),
					reply.interfaces(i).vni(),
					reply.interfaces(i).pcidpname().c_str(),
					reply.interfaces(i).underlayroute().c_str());
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
		dpdk_client.AddInterface();
		std::cout << "Addmachine called " << std::endl;
		printf("IP %s, IPv6 %s PXE Server IP %s PXE Path %s\n", ip_str, ip6_str, pxe_ip_str, pxe_path_str);
		break;
	case DP_CMD_DEL_MACHINE:
		dpdk_client.DelInterface();
		std::cout << "Delmachine called " << std::endl;
		break;
	case DP_CMD_GET_MACHINE:
		std::cout << "Getmachine (single) called " << std::endl;
		dpdk_client.GetInterface();
		break;
	case DP_CMD_LIST_MACHINES:
		std::cout << "Getmachine called " << std::endl;
		dpdk_client.GetInterfaces();
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
	case DP_CMD_LIST_LB_VIP:
		std::cout << "List back IPs called " << std::endl;
		dpdk_client.ListBackIPs();
		break;
	case DP_CMD_ADD_PFX:
		dpdk_client.AddPfx();
		std::cout << "Addprefix called " << std::endl;
		break;
	case DP_CMD_DEL_PFX:
		dpdk_client.DelPfx();
		std::cout << "Delprefix called " << std::endl;
		break;
	case DP_CMD_LIST_PFX:
		std::cout << "Listprefix called " << std::endl;
		dpdk_client.ListPfx();
		break;
	case DP_CMD_INITIALIZED:
		std::cout << "Initialized called " << std::endl;
		dpdk_client.Initialized();
		break;
	case DP_CMD_INIT:
		std::cout << "Init called " << std::endl;
		dpdk_client.Init();
		break;
	case DP_CMD_CREATE_LB:
		std::cout << "Create Loadbalancer called " << std::endl;
		dpdk_client.CreateLB();
		printf("VIP %s, vni %s\n", ip_str, vni_str);
		break;
	case DP_CMD_GET_LB:
		std::cout << "Get Loadbalancer called " << std::endl;
		dpdk_client.GetLB();
		break;
	case DP_CMD_DEL_LB:
		std::cout << "Delete Loadbalancer called " << std::endl;
		dpdk_client.DelLB();
		break;
	default:
		break;
	}

	return 0;
}
