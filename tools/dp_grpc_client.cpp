#include <iostream>
#include <getopt.h>
#include <memory>
#include <string>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <grpcpp/grpcpp.h>

#include "../proto/dpdk.grpc.pb.h"
#include "../include/dp_version.h"

#define CALL_GRPC(FUNC, CTX, REQ, REP) do { \
	grpc::Status status = stub_->FUNC(CTX, REQ, REP); \
	int err = status.error_code(); \
	if (err) { \
		printf("gRPC call '%s' failed with error code %d, message '%s'\n", \
				#FUNC, err, status.error_message().c_str()); \
		exit(0); \
	} \
	err = (REP)->status().code(); \
	if (err) { \
		printf("gRPC call '%s' reply with error code %d, message '%s'\n", \
				#FUNC, err, (REP)->status().message().c_str()); \
		exit(0); \
	} \
} while (0)

using grpc::Channel;
using grpc::ClientContext;
using namespace dpdkonmetal::v1;
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
	DP_CMD_GET_VNI,
	DP_CMD_RESET_VNI,
	DP_CMD_ADD_VIP,
	DP_CMD_DEL_VIP,
	DP_CMD_GET_VIP,
	DP_CMD_ADD_LB_VIP,
	DP_CMD_DEL_LB_VIP,
	DP_CMD_LIST_LB_VIP,
	DP_CMD_ADD_PFX,
	DP_CMD_LIST_PFX,
	DP_CMD_DEL_PFX,
	DP_CMD_ADD_LBPFX,
	DP_CMD_LIST_LBPFX,
	DP_CMD_DEL_LBPFX,
	DP_CMD_INITIALIZED,
	DP_CMD_ADD_NAT_VIP,
	DP_CMD_DEL_NAT_VIP,
	DP_CMD_GET_NAT_VIP,
	DP_CMD_GET_NAT_INFO,
	DP_CMD_ADD_NEIGH_NAT,
	DP_CMD_DEL_NEIGH_NAT,
	DP_CMD_INIT,
	DP_CMD_CREATE_LB,
	DP_CMD_DEL_LB,
	DP_CMD_GET_LB,
	DP_CMD_ADD_FWALL_RULE,
	DP_CMD_GET_FWALL_RULE,
	DP_CMD_DEL_FWALL_RULE,
	DP_CMD_LIST_FWALL_RULE,
	DP_CMD_GET_VERSION,
} cmd_type;

static char ip6_str[40] = {0};
static char t_ip6_str[40] = {0};
static char vni_str[30] = {0};
static char len_str[30] = {0};
static char src_len_str[30] = {0};
static char dst_len_str[30] = {0};
static char t_vni_str[30] = {0};
static char machine_str[64] = {0};
static char lb_id_str[64] = {0};
static char fwall_id_str[64] = {0};
static char ip_str[30] = {0};
static char src_ip_str[30] = {0};
static char dst_ip_str[30] = {0};
static char back_ip_str[30] = {0};
static char pxe_ip_str[30] = {0};
static char vm_pci_str[30] = {0};
static char pxe_path_str[30] = {0};
static char port_str[30] = {0};
static char proto_str[30] = {0};
static char action_str[30] = {0};
static char dir_str[30] = {0};
static char prio_str[30] = {0};
static char min_port_str[30]={0};
static char max_port_str[30]={0};
static char src_port_min_str[30]={0};
static char src_port_max_str[30]={0};
static char dst_port_min_str[30]={0};
static char dst_port_max_str[30]={0};
static char icmp_code_str[30]={0};
static char icmp_type_str[30]={0};
static IpVersion version;
static char get_nat_info_type_str[10]={0};

static int command;
static int debug_mode;
static int vni;
static int t_vni;
static int length, src_length, dst_length;
static bool pfx_lb_enabled = false;
static int min_port, src_port_min = -1, dst_port_min = -1, icmp_code = -1;
static int max_port, src_port_max = -1, dst_port_max = -1, icmp_type = -1;
static uint32_t priority = 1000;

#define CMD_LINE_OPT_INIT			"init"
#define CMD_LINE_OPT_INITIALIZED	"is_initialized"
#define CMD_LINE_OPT_PCI			"vm_pci"
#define CMD_LINE_OPT_ADD_PFX		"addpfx"
#define CMD_LINE_OPT_LIST_PFX		"listpfx"
#define CMD_LINE_OPT_DEL_PFX		"delpfx"
#define CMD_LINE_OPT_ADD_LBPFX		"addlbpfx"
#define CMD_LINE_OPT_LIST_LBPFX		"listlbpfx"
#define CMD_LINE_OPT_DEL_LBPFX		"dellbpfx"
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
#define CMD_LINE_OPT_ADD_NAT_VIP	"addnat"
#define CMD_LINE_OPT_DEL_NAT_VIP	"delnat"
#define CMD_LINE_OPT_GET_NAT_VIP	"getnat"
#define CMD_LINE_OPT_ADD_NEIGH_NAT 	"addneighnat"
#define CMD_LINE_OPT_DEL_NEIGH_NAT 	"delneighnat"
#define CMD_LINE_OPT_GET_NAT_INFO	"getnatinfo"
#define CMD_LINE_OPT_NAT_MIN_PORT	"min_port"
#define CMD_LINE_OPT_NAT_MAX_PORT	"max_port"
#define CMD_LINE_OPT_FWALL_RULE_ID	"fw_ruleid"
#define CMD_LINE_OPT_DEL_FWALL_RULE	"delfwrule"
#define CMD_LINE_OPT_GET_FWALL_RULE	"getfwrule"
#define CMD_LINE_OPT_ADD_FWALL_RULE	"addfwrule"
#define CMD_LINE_OPT_LST_FWALL_RULE	"listfwrules"
#define CMD_LINE_OPT_FWALL_SRC_IP	"src_ip"
#define CMD_LINE_OPT_FWALL_SRC_LEN	"src_length"
#define CMD_LINE_OPT_FWALL_DST_IP	"dst_ip"
#define CMD_LINE_OPT_FWALL_DST_LEN	"dst_length"
#define CMD_LINE_OPT_FWALL_SRC_MIN	"src_port_min"
#define CMD_LINE_OPT_FWALL_SRC_MAX	"src_port_max"
#define CMD_LINE_OPT_FWALL_ICMP_COD	"icmp_code"
#define CMD_LINE_OPT_FWALL_ICMP_TYP	"icmp_type"
#define CMD_LINE_OPT_FWALL_DST_MIN	"dst_port_min"
#define CMD_LINE_OPT_FWALL_DST_MAX	"dst_port_max"
#define CMD_LINE_OPT_FWALL_DIR		"direction"
#define CMD_LINE_OPT_FWALL_ACTION	"action"
#define CMD_LINE_OPT_FWALL_PRIO		"priority"
#define CMD_LINE_OPT_VNI_IN_USE		"vni_in_use"
#define CMD_LINE_OPT_RESET_VNI		"reset_vni"
#define CMD_LINE_OPT_GET_VERSION	"getver"

enum {
	CMD_LINE_OPT_MIN_NUM = 256,
	CMD_LINE_OPT_ADD_MACHINE_NUM,
	CMD_LINE_OPT_DEL_MACHINE_NUM,
	CMD_LINE_OPT_GET_MACHINE_NUM,
	CMD_LINE_OPT_LIST_MACHINES_NUM,
	CMD_LINE_OPT_ADD_ROUTE_NUM,
	CMD_LINE_OPT_DEL_ROUTE_NUM,
	CMD_LINE_OPT_GET_ROUTE_NUM,
	CMD_LINE_OPT_VNI_IN_USE_NUM,
	CMD_LINE_OPT_RESET_VNI_NUM,
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
	CMD_LINE_OPT_ADD_LBPFX_NUM,
	CMD_LINE_OPT_LIST_LBPFX_NUM,
	CMD_LINE_OPT_DEL_LBPFX_NUM,
	CMD_LINE_OPT_INITIALIZED_NUM,
	CMD_LINE_OPT_ADD_NAT_VIP_NUM,
	CMD_LINE_OPT_DEL_NAT_VIP_NUM,
	CMD_LINE_OPT_GET_NAT_VIP_NUM,
	CMD_LINE_OPT_NAT_MIN_PORT_NUM,
	CMD_LINE_OPT_NAT_MAX_PORT_NUM,
	CMD_LINE_OPT_ADD_NEIGH_NAT_NUM,
	CMD_LINE_OPT_DEL_NEIGH_NAT_NUM,
	CMD_LINE_OPT_GET_NAT_INFO_NUM,
	CMD_LINE_OPT_INIT_NUM,
	CMD_LINE_OPT_CREATE_LB_NUM,
	CMD_LINE_OPT_DEL_LB_NUM,
	CMD_LINE_OPT_GET_LB_NUM,
	CMD_LINE_OPT_PFX_LB_NUM,
	CMD_LINE_OPT_GET_FWALL_RULE_NUM,
	CMD_LINE_OPT_DEL_FWALL_RULE_NUM,
	CMD_LINE_OPT_ADD_FWALL_RULE_NUM,
	CMD_LINE_OPT_LST_FWALL_RULE_NUM,
	CMD_LINE_OPT_FWALL_SRC_IP_NUM,
	CMD_LINE_OPT_FWALL_SRC_LEN_NUM,
	CMD_LINE_OPT_FWALL_DST_IP_NUM,
	CMD_LINE_OPT_FWALL_DST_LEN_NUM,
	CMD_LINE_OPT_FWALL_SRC_MIN_NUM,
	CMD_LINE_OPT_FWALL_SRC_MAX_NUM,
	CMD_LINE_OPT_FWALL_DST_MIN_NUM,
	CMD_LINE_OPT_FWALL_DST_MAX_NUM,
	CMD_LINE_OPT_FWALL_ICMP_COD_NUM,
	CMD_LINE_OPT_FWALL_ICMP_TYP_NUM,
	CMD_LINE_OPT_FWALL_DIR_NUM,
	CMD_LINE_OPT_FWALL_ACTION_NUM,
	CMD_LINE_OPT_FWALL_PRIO_NUM,
	CMD_LINE_OPT_FWALL_RULE_ID_NUM,
	CMD_LINE_OPT_GET_VERSION_NUM,
};

static const struct option lgopts[] = {
	{CMD_LINE_OPT_ADD_MACHINE, 1, 0, CMD_LINE_OPT_ADD_MACHINE_NUM},
	{CMD_LINE_OPT_DEL_MACHINE, 1, 0, CMD_LINE_OPT_DEL_MACHINE_NUM},
	{CMD_LINE_OPT_GET_MACHINE, 1, 0, CMD_LINE_OPT_GET_MACHINE_NUM},
	{CMD_LINE_OPT_LIST_MACHINES, 0, 0, CMD_LINE_OPT_LIST_MACHINES_NUM},
	{CMD_LINE_OPT_ADD_ROUTE, 0, 0, CMD_LINE_OPT_ADD_ROUTE_NUM},
	{CMD_LINE_OPT_DEL_ROUTE, 0, 0, CMD_LINE_OPT_DEL_ROUTE_NUM},
	{CMD_LINE_OPT_GET_ROUTE, 0, 0, CMD_LINE_OPT_GET_ROUTE_NUM},
	{CMD_LINE_OPT_VNI_IN_USE, 0, 0, CMD_LINE_OPT_VNI_IN_USE_NUM},
	{CMD_LINE_OPT_RESET_VNI, 0, 0, CMD_LINE_OPT_RESET_VNI_NUM},
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
	{CMD_LINE_OPT_ADD_LB_VIP, 0, 0, CMD_LINE_OPT_ADD_LB_VIP_NUM},
	{CMD_LINE_OPT_DEL_LB_VIP, 0, 0, CMD_LINE_OPT_DEL_LB_VIP_NUM},
	{CMD_LINE_OPT_LIST_LB_VIP, 0, 0, CMD_LINE_OPT_LIST_LB_VIP_NUM},
	{CMD_LINE_OPT_ADD_NAT_VIP, 1, 0, CMD_LINE_OPT_ADD_NAT_VIP_NUM},
	{CMD_LINE_OPT_DEL_NAT_VIP, 1, 0, CMD_LINE_OPT_DEL_NAT_VIP_NUM},
	{CMD_LINE_OPT_GET_NAT_VIP, 1, 0, CMD_LINE_OPT_GET_NAT_VIP_NUM},
	{CMD_LINE_OPT_NAT_MIN_PORT, 1, 0, CMD_LINE_OPT_NAT_MIN_PORT_NUM},
	{CMD_LINE_OPT_NAT_MAX_PORT, 1, 0, CMD_LINE_OPT_NAT_MAX_PORT_NUM},
	{CMD_LINE_OPT_GET_NAT_INFO, 1, 0, CMD_LINE_OPT_GET_NAT_INFO_NUM},
	{CMD_LINE_OPT_ADD_NEIGH_NAT, 0, 0, CMD_LINE_OPT_ADD_NEIGH_NAT_NUM},
	{CMD_LINE_OPT_DEL_NEIGH_NAT, 0, 0, CMD_LINE_OPT_DEL_NEIGH_NAT_NUM},
	{CMD_LINE_OPT_ADD_PFX, 1, 0, CMD_LINE_OPT_ADD_PFX_NUM},
	{CMD_LINE_OPT_LIST_PFX, 1, 0, CMD_LINE_OPT_LIST_PFX_NUM},
	{CMD_LINE_OPT_DEL_PFX, 1, 0, CMD_LINE_OPT_DEL_PFX_NUM},
	{CMD_LINE_OPT_ADD_LBPFX, 1, 0, CMD_LINE_OPT_ADD_LBPFX_NUM},
	{CMD_LINE_OPT_LIST_LBPFX, 1, 0, CMD_LINE_OPT_LIST_LBPFX_NUM},
	{CMD_LINE_OPT_DEL_LBPFX, 1, 0, CMD_LINE_OPT_DEL_LBPFX_NUM},
	{CMD_LINE_OPT_INITIALIZED, 0, 0, CMD_LINE_OPT_INITIALIZED_NUM},
	{CMD_LINE_OPT_INIT, 0, 0, CMD_LINE_OPT_INIT_NUM},
	{CMD_LINE_OPT_CREATE_LB, 1, 0, CMD_LINE_OPT_CREATE_LB_NUM},
	{CMD_LINE_OPT_DEL_LB, 1, 0, CMD_LINE_OPT_DEL_LB_NUM},
	{CMD_LINE_OPT_GET_LB, 1, 0, CMD_LINE_OPT_GET_LB_NUM},
	{CMD_LINE_OPT_PFX_LB, 0, 0, CMD_LINE_OPT_PFX_LB_NUM},
	{CMD_LINE_OPT_ADD_FWALL_RULE, 1, 0, CMD_LINE_OPT_ADD_FWALL_RULE_NUM},
	{CMD_LINE_OPT_DEL_FWALL_RULE, 1, 0, CMD_LINE_OPT_DEL_FWALL_RULE_NUM},
	{CMD_LINE_OPT_GET_FWALL_RULE, 1, 0, CMD_LINE_OPT_GET_FWALL_RULE_NUM},
	{CMD_LINE_OPT_LST_FWALL_RULE, 1, 0, CMD_LINE_OPT_LST_FWALL_RULE_NUM},
	{CMD_LINE_OPT_FWALL_ACTION, 1, 0, CMD_LINE_OPT_FWALL_ACTION_NUM},
	{CMD_LINE_OPT_FWALL_DIR, 1, 0, CMD_LINE_OPT_FWALL_DIR_NUM},
	{CMD_LINE_OPT_FWALL_DST_IP, 1, 0, CMD_LINE_OPT_FWALL_DST_IP_NUM},
	{CMD_LINE_OPT_FWALL_DST_LEN, 1, 0, CMD_LINE_OPT_FWALL_DST_LEN_NUM},
	{CMD_LINE_OPT_FWALL_DST_MAX, 1, 0, CMD_LINE_OPT_FWALL_DST_MAX_NUM},
	{CMD_LINE_OPT_FWALL_DST_MIN, 1, 0, CMD_LINE_OPT_FWALL_DST_MIN_NUM},
	{CMD_LINE_OPT_FWALL_PRIO, 1, 0, CMD_LINE_OPT_FWALL_PRIO_NUM},
	{CMD_LINE_OPT_FWALL_SRC_IP, 1, 0, CMD_LINE_OPT_FWALL_SRC_IP_NUM},
	{CMD_LINE_OPT_FWALL_SRC_LEN, 1, 0, CMD_LINE_OPT_FWALL_SRC_LEN_NUM},
	{CMD_LINE_OPT_FWALL_SRC_MAX, 1, 0, CMD_LINE_OPT_FWALL_SRC_MAX_NUM},
	{CMD_LINE_OPT_FWALL_SRC_MIN, 1, 0, CMD_LINE_OPT_FWALL_SRC_MIN_NUM},
	{CMD_LINE_OPT_FWALL_ICMP_COD, 1, 0, CMD_LINE_OPT_FWALL_ICMP_COD_NUM},
	{CMD_LINE_OPT_FWALL_ICMP_TYP, 1, 0, CMD_LINE_OPT_FWALL_ICMP_TYP_NUM},
	{CMD_LINE_OPT_FWALL_RULE_ID, 1, 0, CMD_LINE_OPT_FWALL_RULE_ID_NUM},
	{CMD_LINE_OPT_GET_VERSION, 0, 0, CMD_LINE_OPT_GET_VERSION_NUM},
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

static int parse_args(int argc, char **argv)
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
		case CMD_LINE_OPT_VNI_IN_USE_NUM:
			command = DP_CMD_GET_VNI;
			break;
		case CMD_LINE_OPT_RESET_VNI_NUM:
			command = DP_CMD_RESET_VNI;
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
			version = IpVersion::IPV4;
			break;
		case CMD_LINE_OPT_PRIMARY_IPV6_NUM:
			strncpy(ip6_str, optarg, 39);
			version = IpVersion::IPV6;
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
		case CMD_LINE_OPT_ADD_LBPFX_NUM:
			command = DP_CMD_ADD_LBPFX;
			strncpy(machine_str, optarg, 63);
			break;
		case CMD_LINE_OPT_DEL_LBPFX_NUM:
			command = DP_CMD_DEL_LBPFX;
			strncpy(machine_str, optarg, 63);
			break;
		case CMD_LINE_OPT_LIST_LBPFX_NUM:
			command = DP_CMD_LIST_LBPFX;
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
		case CMD_LINE_OPT_ADD_NAT_VIP_NUM:
			strncpy(machine_str, optarg, 63);
			command = DP_CMD_ADD_NAT_VIP;
			break;
		case CMD_LINE_OPT_DEL_NAT_VIP_NUM:
			strncpy(machine_str, optarg, 63);
			command = DP_CMD_DEL_NAT_VIP;
			break;
		case CMD_LINE_OPT_GET_NAT_VIP_NUM:
			strncpy(machine_str, optarg, 63);
			command = DP_CMD_GET_NAT_VIP;
			break;
		case CMD_LINE_OPT_NAT_MIN_PORT_NUM:
			strncpy(min_port_str, optarg, 29);
			min_port = (uint32_t)atoi(min_port_str);
			break;
		case CMD_LINE_OPT_NAT_MAX_PORT_NUM:
			strncpy(max_port_str, optarg, 29);
			max_port = (uint32_t)atoi(max_port_str);
			break;
		case CMD_LINE_OPT_ADD_NEIGH_NAT_NUM:
			command = DP_CMD_ADD_NEIGH_NAT;
			break;
		case CMD_LINE_OPT_DEL_NEIGH_NAT_NUM:
			command = DP_CMD_DEL_NEIGH_NAT;
			break;
		case CMD_LINE_OPT_GET_NAT_INFO_NUM:
			command = DP_CMD_GET_NAT_INFO;
			strncpy(get_nat_info_type_str, optarg, 9);
			break;
		case CMD_LINE_OPT_GET_FWALL_RULE_NUM:
			strncpy(machine_str, optarg, 63);
			command = DP_CMD_GET_FWALL_RULE;
			break;
		case CMD_LINE_OPT_LST_FWALL_RULE_NUM:
			strncpy(machine_str, optarg, 63);
			command = DP_CMD_LIST_FWALL_RULE;
			break;
		case CMD_LINE_OPT_DEL_FWALL_RULE_NUM:
			strncpy(machine_str, optarg, 63);
			command = DP_CMD_DEL_FWALL_RULE;
			break;
		case CMD_LINE_OPT_ADD_FWALL_RULE_NUM:
			strncpy(machine_str, optarg, 63);
			version = IpVersion::IPV4;
			command = DP_CMD_ADD_FWALL_RULE;
			break;
		case CMD_LINE_OPT_FWALL_SRC_IP_NUM:
			strncpy(src_ip_str, optarg, 29);
			break;
		case CMD_LINE_OPT_FWALL_SRC_LEN_NUM:
			strncpy(src_len_str, optarg, 29);
			src_length = atoi(src_len_str);
			break;
		case CMD_LINE_OPT_FWALL_SRC_MAX_NUM:
			strncpy(src_port_max_str, optarg, 29);
			src_port_max = atoi(src_port_max_str);
			break;
		case CMD_LINE_OPT_FWALL_SRC_MIN_NUM:
			strncpy(src_port_min_str, optarg, 29);
			src_port_min = atoi(src_port_min_str);
			break;
		case CMD_LINE_OPT_FWALL_ICMP_COD_NUM:
			strncpy(icmp_code_str, optarg, 29);
			icmp_code = atoi(icmp_code_str);
			break;
		case CMD_LINE_OPT_FWALL_ICMP_TYP_NUM:
			strncpy(icmp_type_str, optarg, 29);
			icmp_type = atoi(icmp_type_str);
			break;
		case CMD_LINE_OPT_FWALL_DST_IP_NUM:
			strncpy(dst_ip_str, optarg, 29);
			break;
		case CMD_LINE_OPT_FWALL_DST_LEN_NUM:
			strncpy(dst_len_str, optarg, 29);
			dst_length = atoi(dst_len_str);
			break;
		case CMD_LINE_OPT_FWALL_DST_MAX_NUM:
			strncpy(dst_port_max_str, optarg, 29);
			dst_port_max = atoi(dst_port_max_str);
			break;
		case CMD_LINE_OPT_FWALL_DST_MIN_NUM:
			strncpy(dst_port_min_str, optarg, 29);
			dst_port_min = atoi(dst_port_min_str);
			break;
		case CMD_LINE_OPT_FWALL_ACTION_NUM:
			strncpy(action_str, optarg, 29);
			break;
		case CMD_LINE_OPT_FWALL_DIR_NUM:
			strncpy(dir_str, optarg, 29);
			break;
		case CMD_LINE_OPT_FWALL_PRIO_NUM:
			strncpy(prio_str, optarg, 29);
			priority = atoi(prio_str);
			break;
		case CMD_LINE_OPT_FWALL_RULE_ID_NUM:
			strncpy(fwall_id_str, optarg, 63);
			break;
		case CMD_LINE_OPT_GET_VERSION_NUM:
			command = DP_CMD_GET_VERSION;
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
	void CreateInterface() {
			CreateInterfaceRequest request;
			CreateInterfaceResponse response;
			ClientContext context;
			IpConfig *ip_config = new IpConfig();
			PxeConfig *pxe_config = new PxeConfig();
			IpConfig *ipv6_config = new IpConfig();

			ip_config->set_primary_address(ip_str);
			pxe_config->set_boot_filename(pxe_path_str);
			pxe_config->set_next_server(pxe_ip_str);
			ipv6_config->set_primary_address(ip6_str);
			request.set_interface_id(machine_str);
			request.set_vni(vni);
			request.set_allocated_ipv4_config(ip_config);
			request.set_allocated_ipv6_config(ipv6_config);
			request.set_allocated_pxe_config(pxe_config);
			request.set_interface_type(InterfaceType::VIRTUAL);
			if (vm_pci_str[0] != '\0')
				request.set_device_name(vm_pci_str);
			CALL_GRPC(CreateInterface, &context, request, &response);
			printf("Allocated VF for you %s\n", response.vf().name().c_str());
			printf("Received underlay route : %s\n", response.underlay_route().c_str());
	}

	void CreateRoute() {
			CreateRouteRequest request;
			CreateRouteResponse reply;
			ClientContext context;
			Route *route = new Route();
			Prefix *prefix = new Prefix();
			IpAddress *ip = new IpAddress();
			IpAddress *nh = new IpAddress();

			request.set_vni(vni);
			ip->set_ipver(version);
			if (version == IpVersion::IPV4)
				ip->set_address(ip_str);
			else
				ip->set_address(ip6_str);
			prefix->set_allocated_ip(ip);
			prefix->set_length(length);
			route->set_allocated_prefix(prefix);
			nh->set_ipver(IpVersion::IPV6);
			nh->set_address(t_ip6_str);
			route->set_allocated_nexthop_address(nh);
			route->set_nexthop_vni(t_vni);
			route->set_weight(100);
			request.set_allocated_route(route);
			CALL_GRPC(CreateRoute, &context, request, &reply);
			printf("Route added\n");
	}

	void DelRoute() {
			DeleteRouteRequest request;
			DeleteRouteResponse reply;
			ClientContext context;
			Route *route = new Route();
			Prefix *prefix = new Prefix();
			IpAddress *ip = new IpAddress();
			IpAddress *nh = new IpAddress();

			request.set_vni(vni);
			ip->set_ipver(version);
			if (version == IpVersion::IPV4)
				ip->set_address(ip_str);
			else
				ip->set_address(ip6_str);
			prefix->set_allocated_ip(ip);
			prefix->set_length(length);
			route->set_allocated_prefix(prefix);
			nh->set_ipver(IpVersion::IPV6);
			nh->set_address(t_ip6_str);
			route->set_allocated_nexthop_address(nh);
			route->set_nexthop_vni(t_vni);
			route->set_weight(100);
			request.set_allocated_route(route);
			CALL_GRPC(DeleteRoute, &context, request, &reply);
			printf("Route deleted\n");
	}

	void ListRoutes() {
		ListRoutesRequest request;
		ListRoutesResponse reply;
		ClientContext context;
		int i;

		request.set_vni(vni);

		CALL_GRPC(ListRoutes, &context, request, &reply);
		for (i = 0; i < reply.routes_size(); i++) {
			printf("Route prefix %s len %d target vni %d target ipv6 %s\n",
				reply.routes(i).prefix().ip().address().c_str(),
				reply.routes(i).prefix().length(),
				reply.routes(i).nexthop_vni(),
				reply.routes(i).nexthop_address().address().c_str());
		}
	}

	void VniInUse() {
			CheckVniInUseRequest request;
			CheckVniInUseResponse reply;
			ClientContext context;

			request.set_vni(vni);
			request.set_type(VniType::VNI_IPV4);

			CALL_GRPC(CheckVniInUse, &context, request, &reply);
			if (reply.in_use())
				printf("Vni: %d is in use\n", vni);
			else
				printf("Vni: %d is not in use\n", vni);
	}

	void ResetVni() {
			ResetVniRequest request;
			ResetVniResponse reply;
			ClientContext context;

			request.set_vni(vni);
			request.set_type(VniType::VNI_BOTH);

			CALL_GRPC(ResetVni, &context, request, &reply);
			printf("Vni: %d resetted\n", vni);
	}

	void CreateLBTarget() {
			CreateLoadBalancerTargetRequest request;
			CreateLoadBalancerTargetResponse reply;
			ClientContext context;
			IpAddress *target_ip = new IpAddress();

			request.set_loadbalancer_id(lb_id_str);
			target_ip->set_ipver(IpVersion::IPV6);
			target_ip->set_address(t_ip6_str);
			request.set_allocated_target_ip(target_ip);
			CALL_GRPC(CreateLoadBalancerTarget, &context, request, &reply);
			printf("LB VIP added\n");
	}

	void DelLBTarget() {
			DeleteLoadBalancerTargetRequest request;
			DeleteLoadBalancerTargetResponse reply;
			ClientContext context;
			IpAddress *target_ip = new IpAddress();

			request.set_loadbalancer_id(lb_id_str);
			target_ip->set_ipver(IpVersion::IPV6);
			target_ip->set_address(t_ip6_str);
			request.set_allocated_target_ip(target_ip);
			CALL_GRPC(DeleteLoadBalancerTarget, &context, request, &reply);
			printf("LB VIP deleted\n");
	}

	void ListLBTargets() {
		ListLoadBalancerTargetsRequest request;
		ListLoadBalancerTargetsResponse reply;
		ClientContext context;
		int i;

		request.set_loadbalancer_id(lb_id_str);

		CALL_GRPC(ListLoadBalancerTargets, &context, request, &reply);
		for (i = 0; i < reply.target_ips_size(); i++)
			printf("Backend ip %s\n", reply.target_ips(i).address().c_str());
	}

	void CreateFirewallRule() {
			CreateFirewallRuleRequest request;
			CreateFirewallRuleResponse reply;
			ClientContext context;
			Prefix *src_pfx = new Prefix();
			Prefix *dst_pfx = new Prefix();
			IpAddress *src_ip = new IpAddress();
			IpAddress *dst_ip = new IpAddress();
			ProtocolFilter *filter = new ProtocolFilter();
			FirewallRule *rule = new FirewallRule();
			IcmpFilter *icmp_filter;
			TcpFilter *tcp_filter;
			UdpFilter *udp_filter;

			request.set_interface_id(machine_str);
			rule->set_id(fwall_id_str);
			rule->set_priority(priority);
			if (strncasecmp("ingress", dir_str, 29) == 0)
				rule->set_direction(TrafficDirection::INGRESS);
			else
				rule->set_direction(TrafficDirection::EGRESS);

			if (strncasecmp("accept", action_str, 29) == 0)
				rule->set_action(FirewallAction::ACCEPT);
			else
				rule->set_action(FirewallAction::DROP);

			src_ip->set_ipver(version);
			if (version == IpVersion::IPV4)
				src_ip->set_address(src_ip_str);
			src_pfx->set_allocated_ip(src_ip);
			src_pfx->set_length(src_length);
			rule->set_allocated_source_prefix(src_pfx);

			dst_ip->set_ipver(version);
			if (version == IpVersion::IPV4)
				dst_ip->set_address(dst_ip_str);
			dst_pfx->set_allocated_ip(dst_ip);
			dst_pfx->set_length(dst_length);
			rule->set_allocated_destination_prefix(dst_pfx);

			if (strncasecmp("tcp", proto_str, 29) == 0) {
				tcp_filter = new TcpFilter();
				tcp_filter->set_dst_port_lower(dst_port_min);
				tcp_filter->set_dst_port_upper(dst_port_max);
				tcp_filter->set_src_port_lower(src_port_min);
				tcp_filter->set_src_port_upper(src_port_max);
				filter->set_allocated_tcp(tcp_filter);
				rule->set_allocated_protocol_filter(filter);
			}
			if (strncasecmp("udp", proto_str, 29) == 0) {
				udp_filter = new UdpFilter();
				udp_filter->set_dst_port_lower(dst_port_min);
				udp_filter->set_dst_port_upper(dst_port_max);
				udp_filter->set_src_port_lower(src_port_min);
				udp_filter->set_src_port_upper(src_port_max);
				filter->set_allocated_udp(udp_filter);
				rule->set_allocated_protocol_filter(filter);
			}
			if (strncasecmp("icmp", proto_str, 29) == 0) {
				icmp_filter = new IcmpFilter();
				icmp_filter->set_icmp_code(icmp_code);
				icmp_filter->set_icmp_type(icmp_type);
				filter->set_allocated_icmp(icmp_filter);
				rule->set_allocated_protocol_filter(filter);
			}

			request.set_allocated_rule(rule);
			CALL_GRPC(CreateFirewallRule, &context, request, &reply);
			printf("Firewall rule created\n");
	}

	void DelFirewallRule() {
			DeleteFirewallRuleRequest request;
			DeleteFirewallRuleResponse reply;
			ClientContext context;

			request.set_interface_id(machine_str);
			request.set_rule_id(fwall_id_str);
			CALL_GRPC(DeleteFirewallRule, &context, request, &reply);
			printf("Firewall rule deleted\n");
	}

	void ListFirewallRules() {
		ListFirewallRulesRequest request;
		ListFirewallRulesResponse reply;
		ClientContext context;
		int i;

		request.set_interface_id(machine_str);

		CALL_GRPC(ListFirewallRules, &context, request, &reply);
			for (i = 0; i < reply.rules_size(); i++) {
				printf("%s / ", reply.rules(i).id().c_str());
				if (reply.rules(i).source_prefix().ip().ipver() == IpVersion::IPV4) {
					printf("src_ip: %s / ", reply.rules(i).source_prefix().ip().address().c_str());
					printf("src_ip pfx length: %d / ", reply.rules(i).source_prefix().length());
				}

				if (reply.rules(i).destination_prefix().ip().ipver() == IpVersion::IPV4) {
					printf("dst_ip: %s / ", reply.rules(i).destination_prefix().ip().address().c_str());
					printf("dst_ip pfx length: %d \n", reply.rules(i).destination_prefix().length());
				}

				switch (reply.rules(i).protocol_filter().filter_case()) {
					case ProtocolFilter::kTcpFieldNumber:
						printf("protocol: tcp / src_port_min: %d / src_port_max: %d / dst_port_min: %d / dst_port_max: %d \n",
						reply.rules(i).protocol_filter().tcp().src_port_lower(),
						reply.rules(i).protocol_filter().tcp().src_port_upper(),
						reply.rules(i).protocol_filter().tcp().dst_port_lower(),
						reply.rules(i).protocol_filter().tcp().dst_port_upper());
					break;
					case ProtocolFilter::kUdpFieldNumber:
						printf("protocol: udp / src_port_min: %d / src_port_max: %d / dst_port_min: %d / dst_port_max: %d \n",
						reply.rules(i).protocol_filter().tcp().src_port_lower(),
						reply.rules(i).protocol_filter().tcp().src_port_upper(),
						reply.rules(i).protocol_filter().tcp().dst_port_lower(),
						reply.rules(i).protocol_filter().tcp().dst_port_upper());
					break;
					case ProtocolFilter::kIcmpFieldNumber:
						printf("protocol: icmp / icmp_type: %d / icmp_code: %d \n",
						reply.rules(i).protocol_filter().icmp().icmp_type(),
						reply.rules(i).protocol_filter().icmp().icmp_code());
					break;
					case ProtocolFilter::FILTER_NOT_SET:
						printf("protocol: any / src_port_min: any / dst_port_min: any\n");
					break;
				}
				if (reply.rules(i).direction() == TrafficDirection::INGRESS)
					printf("direction: ingress / ");
				else
					printf("direction: egress / ");

				if (reply.rules(i).action() == FirewallAction::ACCEPT)
					printf("action: accept \n");
				else
					printf("direction: drop \n");
			}
	}

	void GetFirewallRule() {
			GetFirewallRuleRequest request;
			GetFirewallRuleResponse reply;
			ClientContext context;

			request.set_interface_id(machine_str);
			request.set_rule_id(fwall_id_str);
			CALL_GRPC(GetFirewallRule, &context, request, &reply);
				printf("%s / ", reply.rule().id().c_str());
				if (reply.rule().source_prefix().ip().ipver() == IpVersion::IPV4) {
					printf("src_ip: %s / ", reply.rule().source_prefix().ip().address().c_str());
					printf("src_ip pfx length: %d / ", reply.rule().source_prefix().length());
				}

				if (reply.rule().destination_prefix().ip().ipver() == IpVersion::IPV4) {
					printf("dst_ip: %s / ", reply.rule().destination_prefix().ip().address().c_str());
					printf("dst_ip pfx length: %d \n", reply.rule().destination_prefix().length());
				}

				switch (reply.rule().protocol_filter().filter_case()) {
					case ProtocolFilter::kTcpFieldNumber:
						printf("protocol: tcp / src_port_min: %d / src_port_max: %d / dst_port_min: %d / dst_port_max: %d \n",
						reply.rule().protocol_filter().tcp().src_port_lower(),
						reply.rule().protocol_filter().tcp().src_port_upper(),
						reply.rule().protocol_filter().tcp().dst_port_lower(),
						reply.rule().protocol_filter().tcp().dst_port_upper());
					break;
					case ProtocolFilter::kUdpFieldNumber:
						printf("protocol: udp / src_port_min: %d / src_port_max: %d / dst_port_min: %d / dst_port_max: %d \n",
						reply.rule().protocol_filter().tcp().src_port_lower(),
						reply.rule().protocol_filter().tcp().src_port_upper(),
						reply.rule().protocol_filter().tcp().dst_port_lower(),
						reply.rule().protocol_filter().tcp().dst_port_upper());
					break;
					case ProtocolFilter::kIcmpFieldNumber:
						printf("protocol: icmp / icmp_type: %d / icmp_code: %d \n",
						reply.rule().protocol_filter().icmp().icmp_type(),
						reply.rule().protocol_filter().icmp().icmp_code());
					break;
					case ProtocolFilter::FILTER_NOT_SET:
						printf("protocol: any / src_port_min: any / dst_port_min: any\n");
					break;
				}
				if (reply.rule().direction() == TrafficDirection::INGRESS)
					printf("direction: ingress / ");
				else
					printf("direction: egress / ");

				if (reply.rule().action() == FirewallAction::ACCEPT)
					printf("action: accept \n");
				else
					printf("direction: drop \n");
	}

	void CreateVip() {
			CreateVipRequest request;
			CreateVipResponse reply;
			ClientContext context;
			IpAddress *vip_ip = new IpAddress();

			request.set_interface_id(machine_str);
			vip_ip->set_ipver(version);
			if(version == IpVersion::IPV4)
				vip_ip->set_address(ip_str);
			request.set_allocated_vip_ip(vip_ip);
			CALL_GRPC(CreateVip, &context, request, &reply);
			printf("Received underlay route : %s\n", reply.underlay_route().c_str());
	}

	void CreatePfx() {
			CreatePrefixRequest request;
			CreatePrefixResponse reply;
			ClientContext context;
			Prefix *pfx = new Prefix();
			IpAddress *pfx_ip = new IpAddress();

			request.set_interface_id(machine_str);
			pfx_ip->set_ipver(version);
			if (version == IpVersion::IPV4)
				pfx_ip->set_address(ip_str);
			pfx->set_allocated_ip(pfx_ip);
			pfx->set_length(length);
			request.set_allocated_prefix(pfx);
			CALL_GRPC(CreatePrefix, &context, request, &reply);
			printf("Received underlay route : %s\n", reply.underlay_route().c_str());
	}

	void CreateLBPfx() {
			CreateLoadBalancerPrefixRequest request;
			CreateLoadBalancerPrefixResponse reply;
			ClientContext context;
			Prefix *pfx = new Prefix();
			IpAddress *pfx_ip = new IpAddress();

			request.set_interface_id(machine_str);
			pfx_ip->set_ipver(version);
			if (version == IpVersion::IPV4)
				pfx_ip->set_address(ip_str);
			pfx->set_allocated_ip(pfx_ip);
			pfx->set_length(length);
			request.set_allocated_prefix(pfx);
			CALL_GRPC(CreateLoadBalancerPrefix, &context, request, &reply);
			printf("Received underlay route : %s\n", reply.underlay_route().c_str());
	}

	void CreateLB() {
			CreateLoadBalancerRequest request;
			CreateLoadBalancerResponse reply;
			ClientContext context;
			IpAddress *lb_ip = new IpAddress();
			LbPort *lb_port;
			uint16_t ports[DP_MAX_LB_PORTS];
			uint16_t countpro = 0, countp = 0, i;
			uint16_t final_count = 0;
			char protos[DP_MAX_LB_PORTS][4];
			char *pt;

			request.set_loadbalancer_id(lb_id_str);
			request.set_vni(vni);
			lb_ip->set_ipver(IpVersion::IPV4);
			lb_ip->set_address(ip_str);
			request.set_allocated_loadbalanced_ip(lb_ip);

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
				lb_port = request.add_loadbalanced_ports();
				lb_port->set_port(ports[i]);
				if (strncasecmp("tcp", &protos[i][0], 29) == 0)
					lb_port->set_protocol(Protocol::TCP);
				if (strncasecmp("udp", &protos[i][0], 29) == 0)
					lb_port->set_protocol(Protocol::UDP);
			}

			CALL_GRPC(CreateLoadBalancer, &context, request, &reply);
			printf("Received underlay route : %s\n", reply.underlay_route().c_str());
	}

	void GetLB() {
			GetLoadBalancerRequest request;
			GetLoadBalancerResponse reply;
			ClientContext context;
			int i;

			request.set_loadbalancer_id(lb_id_str);

			CALL_GRPC(GetLoadBalancer, &context, request, &reply);
				printf("Received LB with vni: %d UL: %s LB ip: %s with ports: ", reply.vni(),
					   reply.underlay_route().c_str(), reply.loadbalanced_ip().address().c_str());
				for (i = 0; i < reply.loadbalanced_ports_size(); i++) {
					if (reply.loadbalanced_ports(i).protocol() == TCP)
						printf("%d,%s ", reply.loadbalanced_ports(i).port(), "tcp");
					if (reply.loadbalanced_ports(i).protocol() == UDP)
						printf("%d,%s ", reply.loadbalanced_ports(i).port(), "udp");
				}
				printf("\n");
	}

	void DelLB() {
			DeleteLoadBalancerRequest request;
			DeleteLoadBalancerResponse reply;
			ClientContext context;

			request.set_loadbalancer_id(lb_id_str);

			CALL_GRPC(DeleteLoadBalancer, &context, request, &reply);
			printf("LB deleted\n");
	}

	void Initialized() {
			CheckInitializedRequest request;
			CheckInitializedResponse reply;
			ClientContext context;
			system_clock::time_point deadline = system_clock::now() + seconds(5);

			context.set_deadline(deadline);
			reply.set_uuid("");

			/* Aborted answers mean that dp-service is not initialized with init() call yet */
			/* So do not exit with error in that case */
			grpc::Status ret = stub_->CheckInitialized(&context, request, &reply);
			if ((reply.uuid().c_str()[0] == '\0') && (ret.error_code() != grpc::StatusCode::ABORTED))
				exit(1);
			printf("Received UUID %s\n", reply.uuid().c_str());
	}

	void Init() {
			InitializeRequest request;
			InitializeResponse reply;
			ClientContext context;
			system_clock::time_point deadline = system_clock::now() + seconds(5);

			context.set_deadline(deadline);

			CALL_GRPC(Initialize, &context, request, &reply);
			printf("Initialized\n");
			printf("Received UUID %s\n", reply.uuid().c_str());
	}

	void DelPfx() {
			DeletePrefixRequest request;
			DeletePrefixResponse reply;
			ClientContext context;
			Prefix *pfx = new Prefix();
			IpAddress *pfx_ip = new IpAddress();

			request.set_interface_id(machine_str);
			pfx_ip->set_ipver(version);
			if (version == IpVersion::IPV4)
				pfx_ip->set_address(ip_str);
			pfx->set_allocated_ip(pfx_ip);
			pfx->set_length(length);
			request.set_allocated_prefix(pfx);
			CALL_GRPC(DeletePrefix, &context, request, &reply);
			printf("Prefix deleted\n");
	}

	void ListPfx() {
		ListPrefixesRequest request;
		ListPrefixesResponse reply;
		ClientContext context;
		int i;

		request.set_interface_id(machine_str);

		CALL_GRPC(ListPrefixes, &context, request, &reply);
		for (i = 0; i < reply.prefixes_size(); i++) {
			printf("Route prefix %s len %d underlayroute %s\n",
				reply.prefixes(i).ip().address().c_str(),
				reply.prefixes(i).length(),
				reply.prefixes(i).underlay_route().c_str());
		}
	}

	void DelLBPfx() {
			DeleteLoadBalancerPrefixRequest request;
			DeleteLoadBalancerPrefixResponse reply;
			ClientContext context;
			Prefix *pfx = new Prefix();
			IpAddress *pfx_ip = new IpAddress();

			request.set_interface_id(machine_str);
			pfx_ip->set_ipver(version);
			if (version == IpVersion::IPV4)
				pfx_ip->set_address(ip_str);
			pfx->set_allocated_ip(pfx_ip);
			pfx->set_length(length);
			request.set_allocated_prefix(pfx);
			CALL_GRPC(DeleteLoadBalancerPrefix, &context, request, &reply);
			printf("LB prefix deleted\n");
	}

	void ListLBPfx() {
		ListLoadBalancerPrefixesRequest request;
		ListLoadBalancerPrefixesResponse reply;
		ClientContext context;
		int i;

		request.set_interface_id(machine_str);

		CALL_GRPC(ListLoadBalancerPrefixes, &context, request, &reply);
		for (i = 0; i < reply.prefixes_size(); i++) {
			printf("LB Route prefix %s len %d underlayroute %s\n",
				reply.prefixes(i).ip().address().c_str(),
				reply.prefixes(i).length(),
				reply.prefixes(i).underlay_route().c_str());
		}
	}

	void DelVip() {
			DeleteVipRequest request;
			DeleteVipResponse reply;
			ClientContext context;

			request.set_interface_id(machine_str);
			CALL_GRPC(DeleteVip, &context, request, &reply);
			printf("VIP deleted\n");
	}

	void GetVip() {
			GetVipRequest request;
			GetVipResponse reply;
			ClientContext context;

			request.set_interface_id(machine_str);
			CALL_GRPC(GetVip, &context, request, &reply);
			printf("Received VIP %s underlayroute %s\n",
				   reply.vip_ip().address().c_str(), reply.underlay_route().c_str());
	}

	void DelInterface() {
			DeleteInterfaceRequest request;
			DeleteInterfaceResponse reply;
			ClientContext context;

			request.set_interface_id(machine_str);
			CALL_GRPC(DeleteInterface, &context, request, &reply);
			printf("Interface deleted\n");
	}

	void GetInterface() {
			GetInterfaceRequest request;
			GetInterfaceResponse reply;
			ClientContext context;

			request.set_interface_id(machine_str);
			CALL_GRPC(GetInterface, &context, request, &reply);
			printf("Interface with ipv4 %s ipv6 %s vni %d pci %s underlayroute %s\n",
			reply.interface().primary_ipv4().c_str(),
			reply.interface().primary_ipv6().c_str(),
			reply.interface().vni(),
			reply.interface().pci_name().c_str(),
			reply.interface().underlay_route().c_str());
	}

	void ListInterfaces() {
		ListInterfacesRequest request;
		ListInterfacesResponse reply;
		ClientContext context;
		int i;

		CALL_GRPC(ListInterfaces, &context, request, &reply);
		for (i = 0; i < reply.interfaces_size(); i++) {
			printf("Interface %s ipv4 %s ipv6 %s vni %d pci %s underlayroute %s\n", reply.interfaces(i).id().c_str(),
				reply.interfaces(i).primary_ipv4().c_str(),
				reply.interfaces(i).primary_ipv6().c_str(),
				reply.interfaces(i).vni(),
				reply.interfaces(i).pci_name().c_str(),
				reply.interfaces(i).underlay_route().c_str());
		}
	}

	void CreateNat() {
		CreateNatRequest request;
		CreateNatResponse reply;
		ClientContext context;
		IpAddress *nat_ip = new IpAddress();

		request.set_interface_id(machine_str);
		nat_ip->set_ipver(version);
		if(version == IpVersion::IPV4)
			nat_ip->set_address(ip_str);
		request.set_allocated_nat_ip(nat_ip);
		request.set_min_port(min_port);
		request.set_max_port(max_port);
		CALL_GRPC(CreateNat, &context, request, &reply);
		printf("Received underlay route : %s\n", reply.underlay_route().c_str());
	}

	void DelNat() {
		DeleteNatRequest request;
		DeleteNatResponse reply;
		ClientContext context;

		request.set_interface_id(machine_str);
		CALL_GRPC(DeleteNat, &context, request, &reply);
		printf("NAT deleted\n");
	}

	void GetNat() {
		GetNatRequest request;
		GetNatResponse reply;
		ClientContext context;

		request.set_interface_id(machine_str);
		CALL_GRPC(GetNat, &context, request, &reply);
		printf("Received NAT IP %s with min port: %d and max port: %d underlay %s\n",
				reply.nat_ip().address().c_str(), reply.min_port(), reply.max_port(),
				reply.underlay_route().c_str());
	}

	void CreateNeighNat() {
		CreateNeighborNatRequest request;
		CreateNeighborNatResponse reply;
		ClientContext context;
		IpAddress *nat_ip = new IpAddress();

		nat_ip->set_ipver(version);
		if(version == IpVersion::IPV4) {
			nat_ip->set_address(ip_str);
		} else {
			nat_ip->set_address(ip6_str);
		}

		request.set_allocated_nat_ip(nat_ip);
		request.set_vni(vni);
		request.set_min_port(min_port);
		request.set_max_port(max_port);
		request.set_underlay_route(t_ip6_str);

		CALL_GRPC(CreateNeighborNat, &context, request, &reply);
		printf("Neighbor NAT added\n");
	}

	void ListLocalNats() {
		ListLocalNatsRequest request;
		ListLocalNatsResponse reply;
		ClientContext context;
		IpAddress *nat_ip = new IpAddress();
		int i;

		nat_ip->set_ipver(version);
		if (version == IpVersion::IPV4)
			nat_ip->set_address(ip_str);
		else
			nat_ip->set_address(ip6_str);
		request.set_allocated_nat_ip(nat_ip);

		CALL_GRPC(ListLocalNats, &context, request, &reply);
		printf("Following private IPs are NAT into this IPv4 NAT address: %s\n", nat_ip->address().c_str());
		for (i = 0; i < reply.nat_entries_size(); i++) {
			printf("  %d: IP %s, min_port %u, max_port %u, vni: %u\n", i+1,
			reply.nat_entries(i).nat_ip().address().c_str(),
			reply.nat_entries(i).min_port(),
			reply.nat_entries(i).max_port(),
			reply.nat_entries(i).vni());
		}
	}
	void ListNeighNATs() {
		ListNeighborNatsRequest request;
		ListNeighborNatsResponse reply;
		ClientContext context;
		IpAddress *nat_ip = new IpAddress();
		int i;

		nat_ip->set_ipver(version);
		if (version == IpVersion::IPV4)
			nat_ip->set_address(ip_str);
		else
			nat_ip->set_address(ip6_str);
		request.set_allocated_nat_ip(nat_ip);

		CALL_GRPC(ListNeighborNats, &context, request, &reply);
		printf("Following port ranges and their route of neighbor NAT exists for this IPv4 NAT address: %s\n", nat_ip->address().c_str());
		for (i = 0; i < reply.nat_entries_size(); i++) {
			printf("  %d: min_port %u, max_port %u, vni %u --> Underlay IPv6 %s\n", i+1,
			reply.nat_entries(i).min_port(),
			reply.nat_entries(i).max_port(),
			reply.nat_entries(i).vni(),
			reply.nat_entries(i).underlay_route().c_str());
		}
	}
	void GetNatEntries() {
		if (!strcmp(get_nat_info_type_str, "local"))
			ListLocalNats();
		else if (!strcmp(get_nat_info_type_str, "neigh"))
			ListNeighNATs();
		else
			printf("Wrong query nat info type parameter, either local or neigh\n");
	}

	void DelNeighNat() {
		DeleteNeighborNatRequest request;
		DeleteNeighborNatResponse reply;
		ClientContext context;
		IpAddress *nat_ip = new IpAddress();

		nat_ip->set_ipver(version);
		if(version == IpVersion::IPV4) {
			nat_ip->set_address(ip_str);
		} else {
			nat_ip->set_address(ip6_str);
		}

		request.set_allocated_nat_ip(nat_ip);
		request.set_vni(vni);
		request.set_min_port(min_port);
		request.set_max_port(max_port);

		CALL_GRPC(DeleteNeighborNat, &context, request, &reply);
		printf("Neighbor NAT deleted\n");
	}

	void GetVersion() {
		GetVersionRequest request;
		GetVersionResponse reply;
		ClientContext context;

		request.set_client_protocol(DP_SERVICE_VERSION);
		request.set_client_name("dp_grpc_client");
		request.set_client_version(DP_SERVICE_VERSION);

		CALL_GRPC(GetVersion, &context, request, &reply);
		printf("Got protocol '%s' on service '%s'\n", reply.service_protocol().c_str(), reply.service_version().c_str());
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
		dpdk_client.CreateInterface();
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
		dpdk_client.ListInterfaces();
		break;
	case DP_CMD_ADD_ROUTE:
		dpdk_client.CreateRoute();
		std::cout << "Addroute called " << std::endl;
		printf("Route ip %s length %d vni %d target ipv6 %s target vni %d\n", ip_str, length, vni, ip6_str, t_vni);
		break;
	case DP_CMD_GET_ROUTE:
		std::cout << "Listroute called " << std::endl;
		dpdk_client.ListRoutes();
		break;
	case DP_CMD_GET_VNI:
		std::cout << "IsVniInUse called " << std::endl;
		dpdk_client.VniInUse();
		break;
	case DP_CMD_RESET_VNI:
		std::cout << "ResetVni called " << std::endl;
		dpdk_client.ResetVni();
		break;
	case DP_CMD_DEL_ROUTE:
		dpdk_client.DelRoute();
		std::cout << "Delroute called " << std::endl;
		break;
	case DP_CMD_ADD_VIP:
		dpdk_client.CreateVip();
		std::cout << "Addvip called " << std::endl;
		break;
	case DP_CMD_DEL_VIP:
		dpdk_client.DelVip();
		std::cout << "Delvip called " << std::endl;
		break;
	case DP_CMD_GET_VIP:
		std::cout << "Getvip called " << std::endl;
		dpdk_client.GetVip();
		break;
	case DP_CMD_ADD_LB_VIP:
		dpdk_client.CreateLBTarget();
		std::cout << "Addlbvip called " << std::endl;
		break;
	case DP_CMD_DEL_LB_VIP:
		dpdk_client.DelLBTarget();
		std::cout << "Dellbvip called " << std::endl;
		break;
	case DP_CMD_LIST_LB_VIP:
		std::cout << "List back IPs called " << std::endl;
		dpdk_client.ListLBTargets();
		break;
	case DP_CMD_ADD_PFX:
		dpdk_client.CreatePfx();
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
	case DP_CMD_ADD_LBPFX:
		dpdk_client.CreateLBPfx();
		std::cout << "AddLBprefix called " << std::endl;
		break;
	case DP_CMD_DEL_LBPFX:
		dpdk_client.DelLBPfx();
		std::cout << "DelLBprefix called " << std::endl;
		break;
	case DP_CMD_LIST_LBPFX:
		std::cout << "ListLBprefix called " << std::endl;
		dpdk_client.ListLBPfx();
		break;
	case DP_CMD_ADD_NAT_VIP:
		std::cout << "Addnat called " << std::endl;
		dpdk_client.CreateNat();
		break;
	case DP_CMD_GET_NAT_INFO:
		std::cout << "getNATEntry called " << std::endl;
		dpdk_client.GetNatEntries();
		break;
	case DP_CMD_DEL_NAT_VIP:
		std::cout << "Delnat called " << std::endl;
		dpdk_client.DelNat();
		break;
	case DP_CMD_GET_NAT_VIP:
		std::cout << "Getnat called " << std::endl;
		dpdk_client.GetNat();
		break;
	case DP_CMD_ADD_NEIGH_NAT:
		std::cout << "AddNeighNat called " << std::endl;
		dpdk_client.CreateNeighNat();
		break;
	case DP_CMD_DEL_NEIGH_NAT:
		std::cout << "DelNeighNat called " << std::endl;
		dpdk_client.DelNeighNat();
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
	case DP_CMD_ADD_FWALL_RULE:
		std::cout << "Add FirewallRule called " << std::endl;
		dpdk_client.CreateFirewallRule();
		break;
	case DP_CMD_GET_FWALL_RULE:
		std::cout << "Get FirewallRule called " << std::endl;
		dpdk_client.GetFirewallRule();
		break;
	case DP_CMD_LIST_FWALL_RULE:
		std::cout << "List FirewallRules called " << std::endl;
		dpdk_client.ListFirewallRules();
		break;
	case DP_CMD_DEL_FWALL_RULE:
		std::cout << "Del FirewallRule called " << std::endl;
		dpdk_client.DelFirewallRule();
		break;
	case DP_CMD_GET_VERSION:
		std::cout << "Get Version called " << std::endl;
		dpdk_client.GetVersion();
		break;
	default:
		break;
	}

	return 0;
}
