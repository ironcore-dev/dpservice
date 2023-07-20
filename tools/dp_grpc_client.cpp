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
static IPVersion version;
static char get_nat_info_type_str[10]={0};

static int command;
static int debug_mode;
static int vni;
static int t_vni;
static int length, src_length, dst_length;
static bool pfx_lb_enabled = false;
static int min_port, src_port_min, dst_port_min, icmp_code;
static int max_port, src_port_max, dst_port_max, icmp_type;
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
			version = IPVersion::IPv4;
			break;
		case CMD_LINE_OPT_PRIMARY_IPV6_NUM:
			strncpy(ip6_str, optarg, 39);
			version = IPVersion::IPv6;
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
			version = IPVersion::IPv4;
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
			request.set_interfacetype(InterfaceType::VirtualInterface);
			if (vm_pci_str[0] != '\0')
				request.set_devicename(vm_pci_str);
			stub_->CreateInterface(&context, request, &response);
			if (!response.status().error()) {
				printf("Allocated VF for you %s\n", response.vf().name().c_str());
				printf("Received underlay route : %s\n", response.underlayroute().c_str());
			} else {
				printf("Received an error %d\n", response.status().error());
			}
	}

	void CreateRoute() {
			CreateRouteRequest request;
			CreateRouteResponse reply;
			ClientContext context;
			Route *route = new Route();
			Prefix *prefix = new Prefix();

			request.set_vni(vni);
			prefix->set_ipversion(version);
			if(version == IPVersion::IPv4) {
				prefix->set_address(ip_str);
			} else {
				prefix->set_address(ip6_str);
			}
			prefix->set_prefixlength(length);
			route->set_allocated_prefix(prefix);
			route->set_ipversion(IPVersion::IPv6);
			route->set_nexthopvni(t_vni);
			route->set_weight(100);
			route->set_nexthopaddress(t_ip6_str);
			request.set_allocated_route(route);
			stub_->CreateRoute(&context, request, &reply);
			if (reply.status().error())
				printf("Received an error %d\n", reply.status().error());
			else
				printf("Route added\n");
	}

	void DelRoute() {
			DeleteRouteRequest request;
			DeleteRouteResponse reply;
			ClientContext context;
			Route *route = new Route();
			Prefix *prefix = new Prefix();

			request.set_vni(vni);
			prefix->set_ipversion(version);
			if(version == IPVersion::IPv4) {
				prefix->set_address(ip_str);
			} else {
				prefix->set_address(ip6_str);
			}
			prefix->set_prefixlength(length);
			route->set_allocated_prefix(prefix);
			route->set_ipversion(IPVersion::IPv6);
			route->set_nexthopvni(t_vni);
			route->set_weight(100);
			route->set_nexthopaddress(t_ip6_str);
			request.set_allocated_route(route);
			stub_->DeleteRoute(&context, request, &reply);
			if (reply.status().error())
				printf("Received an error %d\n", reply.status().error());
			else
				printf("Route deleted\n");
	}

	void ListRoutes() {
		ListRoutesRequest request;
		ListRoutesResponse reply;
		ClientContext context;
		int i;

		request.set_vni(vni);

		stub_->ListRoutes(&context, request, &reply);
		if (reply.status().error())
			printf("Received an error %d\n", reply.status().error());
		else
			for (i = 0; i < reply.routes_size(); i++) {
				printf("Route prefix %s len %d target vni %d target ipv6 %s\n",
					reply.routes(i).prefix().address().c_str(),
					reply.routes(i).prefix().prefixlength(),
					reply.routes(i).nexthopvni(),
					reply.routes(i).nexthopaddress().c_str());
			}
	}

	void VniInUse() {
			CheckVniInUseRequest request;
			CheckVniInUseResponse reply;
			ClientContext context;

			request.set_vni(vni);
			request.set_type(VniIpv4);

			stub_->CheckVniInUse(&context, request, &reply);
			if (reply.status().error())
				printf("Received an error %d\n", reply.status().error());
			else if (reply.inuse())
				printf("Vni: %d is in use\n", vni);
			else
				printf("Vni: %d is not in use\n", vni);
	}

	void ResetVni() {
			ResetVniRequest request;
			ResetVniResponse reply;
			ClientContext context;

			request.set_vni(vni);
			request.set_type(VniIpv4AndIpv6);

			stub_->ResetVni(&context, request, &reply);
			if (reply.status().error())
				printf("Received an error %d\n", reply.status().error());
			else
				printf("Vni: %d resetted\n", vni);
	}

	void CreateLBTarget() {
			CreateLoadBalancerTargetRequest request;
			CreateLoadBalancerTargetResponse reply;
			ClientContext context;
			LBIP *back_ip = new LBIP();

			request.set_loadbalancerid(lb_id_str);
			back_ip->set_ipversion(IPVersion::IPv6);
			back_ip->set_address(t_ip6_str);
			request.set_allocated_targetip(back_ip);
			stub_->CreateLoadBalancerTarget(&context, request, &reply);
			if (reply.status().error())
				printf("Received an error %d\n", reply.status().error());
			else
				printf("LB VIP added\n");
	}

	void DelLBTarget() {
			DeleteLoadBalancerTargetRequest request;
			DeleteLoadBalancerTargetResponse reply;
			ClientContext context;
			LBIP *back_ip = new LBIP();

			request.set_loadbalancerid(lb_id_str);
			back_ip->set_ipversion(IPVersion::IPv6);
			back_ip->set_address(t_ip6_str);
			request.set_allocated_targetip(back_ip);
			stub_->DeleteLoadBalancerTarget(&context, request, &reply);
			if (reply.status().error())
				printf("Received an error %d\n", reply.status().error());
			else
				printf("LB VIP deleted\n");
	}

	void ListLBTargets() {
		ListLoadBalancerTargetsRequest request;
		ListLoadBalancerTargetsResponse reply;
		ClientContext context;
		int i;

		request.set_loadbalancerid(lb_id_str);

		stub_->ListLoadBalancerTargets(&context, request, &reply);
		if (reply.status().error())
			printf("Received an error %d\n", reply.status().error());
		else
			for (i = 0; i < reply.targetips_size(); i++)
				printf("Backend ip %s\n", reply.targetips(i).address().c_str());
	}

	void CreateFirewallRule() {
			CreateFirewallRuleRequest request;
			CreateFirewallRuleResponse reply;
			ClientContext context;
			Prefix *src_ip = new Prefix();
			Prefix *dst_ip = new Prefix();
			ProtocolFilter *filter = new ProtocolFilter();
			FirewallRule *rule = new FirewallRule();
			ICMPFilter *icmp_filter;
			TCPFilter *tcp_filter;
			UDPFilter *udp_filter;

			request.set_interfaceid(machine_str);
			rule->set_ruleid(fwall_id_str);
			rule->set_ipversion(version);
			rule->set_priority(priority);
			if (strncasecmp("ingress", dir_str, 29) == 0)
				rule->set_direction(Ingress);
			else
				rule->set_direction(Egress);

			if (strncasecmp("accept", action_str, 29) == 0)
				rule->set_action(Accept);
			else
				rule->set_action(Drop);

			src_ip->set_ipversion(version);
			if(version == IPVersion::IPv4)
				src_ip->set_address(src_ip_str);
			src_ip->set_prefixlength(src_length);
			rule->set_allocated_sourceprefix(src_ip);

			dst_ip->set_ipversion(version);
			if(version == IPVersion::IPv4)
				dst_ip->set_address(dst_ip_str);
			dst_ip->set_prefixlength(dst_length);
			rule->set_allocated_destinationprefix(dst_ip);

			if (strncasecmp("tcp", proto_str, 29) == 0) {
				tcp_filter = new TCPFilter();
				tcp_filter->set_dstportlower(dst_port_min);
				tcp_filter->set_dstportupper(dst_port_max);
				tcp_filter->set_srcportlower(src_port_min);
				tcp_filter->set_srcportupper(src_port_max);
				filter->set_allocated_tcp(tcp_filter);
				rule->set_allocated_protocolfilter(filter);
			}
			if (strncasecmp("udp", proto_str, 29) == 0) {
				udp_filter = new UDPFilter();
				udp_filter->set_dstportlower(dst_port_min);
				udp_filter->set_dstportupper(dst_port_max);
				udp_filter->set_srcportlower(src_port_min);
				udp_filter->set_srcportupper(src_port_max);
				filter->set_allocated_udp(udp_filter);
				rule->set_allocated_protocolfilter(filter);
			}
			if (strncasecmp("icmp", proto_str, 29) == 0) {
				icmp_filter = new ICMPFilter();
				icmp_filter->set_icmpcode(icmp_code);
				icmp_filter->set_icmptype(icmp_type);
				filter->set_allocated_icmp(icmp_filter);
				rule->set_allocated_protocolfilter(filter);
			}

			request.set_allocated_rule(rule);
			stub_->CreateFirewallRule(&context, request, &reply);
			if (reply.status().error())
				printf("Received an error %d\n", reply.status().error());
	}

	void DelFirewallRule() {
			DeleteFirewallRuleRequest request;
			DeleteFirewallRuleResponse reply;
			ClientContext context;

			request.set_interfaceid(machine_str);
			request.set_ruleid(fwall_id_str);
			stub_->DeleteFirewallRule(&context, request, &reply);
			if (reply.status().error())
				printf("Received an error %d\n", reply.status().error());
			else
				printf("Firewall Rule Deleted\n");
	}

	void ListFirewallRules() {
		ListFirewallRulesRequest request;
		ListFirewallRulesResponse reply;
		ClientContext context;
		int i;

		request.set_interfaceid(machine_str);

		stub_->ListFirewallRules(&context, request, &reply);
		if (reply.status().error())
			printf("Received an error %d\n", reply.status().error());
		else
			for (i = 0; i < reply.rules_size(); i++) {
				printf("%s / ", reply.rules(i).ruleid().c_str());
				if (reply.rules(i).sourceprefix().ipversion() == IPVersion::IPv4) {
					printf("src_ip: %s / ", reply.rules(i).sourceprefix().address().c_str());
					printf("src_ip pfx length: %d / ", reply.rules(i).sourceprefix().prefixlength());
				}

				if (reply.rules(i).destinationprefix().ipversion() == IPVersion::IPv4) {
					printf("dst_ip: %s / ", reply.rules(i).destinationprefix().address().c_str());
					printf("dst_ip pfx length: %d \n", reply.rules(i).destinationprefix().prefixlength());
				}

				switch (reply.rules(i).protocolfilter().filter_case()) {
					case ProtocolFilter::kTcpFieldNumber:
						printf("protocol: tcp / src_port_min: %d / src_port_max: %d / dst_port_min: %d / dst_port_max: %d \n",
						reply.rules(i).protocolfilter().tcp().srcportlower(),
						reply.rules(i).protocolfilter().tcp().srcportupper(),
						reply.rules(i).protocolfilter().tcp().dstportlower(),
						reply.rules(i).protocolfilter().tcp().dstportupper());
					break;
					case ProtocolFilter::kUdpFieldNumber:
						printf("protocol: udp / src_port_min: %d / src_port_max: %d / dst_port_min: %d / dst_port_max: %d \n",
						reply.rules(i).protocolfilter().tcp().srcportlower(),
						reply.rules(i).protocolfilter().tcp().srcportupper(),
						reply.rules(i).protocolfilter().tcp().dstportlower(),
						reply.rules(i).protocolfilter().tcp().dstportupper());
					break;
					case ProtocolFilter::kIcmpFieldNumber:
						printf("protocol: icmp / icmp_type: %d / icmp_code: %d \n",
						reply.rules(i).protocolfilter().icmp().icmptype(),
						reply.rules(i).protocolfilter().icmp().icmpcode());
					break;
					case ProtocolFilter::FILTER_NOT_SET:
						printf("protocol: any / src_port_min: any / dst_port_min: any\n");
					break;
				}
				if (reply.rules(i).direction() == Ingress)
					printf("direction: ingress / ");
				else
					printf("direction: egress / ");

				if (reply.rules(i).action() == Accept)
					printf("action: accept \n");
				else
					printf("direction: drop \n");
			}

	}

	void GetFirewallRule() {
			GetFirewallRuleRequest request;
			GetFirewallRuleResponse reply;
			ClientContext context;

			request.set_interfaceid(machine_str);
			request.set_ruleid(fwall_id_str);
			stub_->GetFirewallRule(&context, request, &reply);
			if (reply.status().error())
				printf("Received an error %d\n", reply.status().error());
			else {
				printf("%s / ", reply.rule().ruleid().c_str());
				if (reply.rule().sourceprefix().ipversion() == IPVersion::IPv4) {
					printf("src_ip: %s / ", reply.rule().sourceprefix().address().c_str());
					printf("src_ip pfx length: %d / ", reply.rule().sourceprefix().prefixlength());
				}

				if (reply.rule().destinationprefix().ipversion() == IPVersion::IPv4) {
					printf("dst_ip: %s / ", reply.rule().destinationprefix().address().c_str());
					printf("dst_ip pfx length: %d \n", reply.rule().destinationprefix().prefixlength());
				}

				switch (reply.rule().protocolfilter().filter_case()) {
					case ProtocolFilter::kTcpFieldNumber:
						printf("protocol: tcp / src_port_min: %d / src_port_max: %d / dst_port_min: %d / dst_port_max: %d \n",
						reply.rule().protocolfilter().tcp().srcportlower(),
						reply.rule().protocolfilter().tcp().srcportupper(),
						reply.rule().protocolfilter().tcp().dstportlower(),
						reply.rule().protocolfilter().tcp().dstportupper());
					break;
					case ProtocolFilter::kUdpFieldNumber:
						printf("protocol: udp / src_port_min: %d / src_port_max: %d / dst_port_min: %d / dst_port_max: %d \n",
						reply.rule().protocolfilter().tcp().srcportlower(),
						reply.rule().protocolfilter().tcp().srcportupper(),
						reply.rule().protocolfilter().tcp().dstportlower(),
						reply.rule().protocolfilter().tcp().dstportupper());
					break;
					case ProtocolFilter::kIcmpFieldNumber:
						printf("protocol: icmp / icmp_type: %d / icmp_code: %d \n",
						reply.rule().protocolfilter().icmp().icmptype(),
						reply.rule().protocolfilter().icmp().icmpcode());
					break;
					case ProtocolFilter::FILTER_NOT_SET:
						printf("protocol: any / src_port_min: any / dst_port_min: any\n");
					break;
				}
				if (reply.rule().direction() == Ingress)
					printf("direction: ingress / ");
				else
					printf("direction: egress / ");

				if (reply.rule().action() == Accept)
					printf("action: accept \n");
				else
					printf("direction: drop \n");
			}
	}

	void CreateVIP() {
			CreateInterfaceVIPRequest request;
			CreateInterfaceVIPResponse reply;
			ClientContext context;
			InterfaceVIPIP *vip_ip = new InterfaceVIPIP();

			request.set_interfaceid(machine_str);
			vip_ip->set_ipversion(version);
			if(version == IPVersion::IPv4)
				vip_ip->set_address(ip_str);
			request.set_allocated_interfacevipip(vip_ip);
			stub_->CreateInterfaceVIP(&context, request, &reply);
			if (reply.status().error())
				printf("Received an error %d\n", reply.status().error());
			else
				printf("Received underlay route : %s\n", reply.underlayroute().c_str());
	}

	void CreatePfx() {
			CreateInterfacePrefixRequest request;
			CreateInterfacePrefixResponse reply;
			ClientContext context;
			Prefix *pfx_ip = new Prefix();

			request.set_interfaceid(machine_str);
			pfx_ip->set_ipversion(version);
			if(version == IPVersion::IPv4)
				pfx_ip->set_address(ip_str);
			pfx_ip->set_prefixlength(length);
			request.set_allocated_prefix(pfx_ip);
			stub_->CreateInterfacePrefix(&context, request, &reply);
			if (reply.status().error())
				printf("Received an error %d\n", reply.status().error());
			else
				printf("Received underlay route : %s\n", reply.underlayroute().c_str());
	}

	void CreateLBPfx() {
			CreateInterfaceLoadBalancerPrefixRequest request;
			CreateInterfaceLoadBalancerPrefixResponse reply;
			ClientContext context;
			Prefix *pfx_ip = new Prefix();

			request.set_interfaceid(machine_str);
			pfx_ip->set_ipversion(version);
			if(version == IPVersion::IPv4)
				pfx_ip->set_address(ip_str);
			pfx_ip->set_prefixlength(length);
			request.set_allocated_prefix(pfx_ip);
			stub_->CreateInterfaceLoadBalancerPrefix(&context, request, &reply);
			if (reply.status().error())
				printf("Received an error %d\n", reply.status().error());
			else
				printf("Received underlay route : %s\n", reply.underlayroute().c_str());
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
			lb_ip->set_ipversion(IPVersion::IPv4);
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
					lb_port->set_protocol(Protocol::TCP);
				if (strncasecmp("udp", &protos[i][0], 29) == 0)
					lb_port->set_protocol(Protocol::UDP);
			}

			stub_->CreateLoadBalancer(&context, request, &reply);
			if (reply.status().error())
				printf("Received an error %d\n", reply.status().error());
			else
				printf("Received underlay route : %s\n", reply.underlayroute().c_str());
	}

	void GetLB() {
			GetLoadBalancerRequest request;
			GetLoadBalancerResponse reply;
			ClientContext context;
			int i;

			request.set_loadbalancerid(lb_id_str);

			stub_->GetLoadBalancer(&context, request, &reply);
			if (reply.status().error()) {
				printf("Received an error %d\n", reply.status().error());
			} else {
				printf("Received LB with vni: %d UL: %s LB ip: %s with ports: ", reply.vni(),
					   reply.underlayroute().c_str(), reply.lbvipip().address().c_str());
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
			DeleteLoadBalancerResponse reply;
			ClientContext context;

			request.set_loadbalancerid(lb_id_str);

			stub_->DeleteLoadBalancer(&context, request, &reply);
			if (reply.status().error())
				printf("Received an error %d\n", reply.status().error());
			else
				printf("LB deleted\n");
	}

	void Initialized() {
			CheckInitializedRequest request;
			CheckInitializedResponse reply;
			ClientContext context;
			system_clock::time_point deadline = system_clock::now() + seconds(5);

			context.set_deadline(deadline);
			reply.set_uuid("");

			grpc::Status ret = stub_->CheckInitialized(&context, request, &reply);
			/* Aborted answers mean that dp-service is not initialized with init() call yet */
			/* So do not exit with error in that case */
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

			stub_->Initialize(&context, request, &reply);
	}

	void DelPfx() {
			DeleteInterfacePrefixRequest request;
			DeleteInterfacePrefixResponse reply;
			ClientContext context;
			Prefix *pfx_ip = new Prefix();

			request.set_interfaceid(machine_str);
			pfx_ip->set_ipversion(version);
			if(version == IPVersion::IPv4)
				pfx_ip->set_address(ip_str);
			pfx_ip->set_prefixlength(length);
			request.set_allocated_prefix(pfx_ip);
			stub_->DeleteInterfacePrefix(&context, request, &reply);
			if (reply.status().error())
				printf("Received an error %d\n", reply.status().error());
			else
				printf("Prefix deleted\n");
	}

	void ListPfx() {
		ListInterfacePrefixesRequest request;
		ListInterfacePrefixesResponse reply;
		ClientContext context;
		int i;

		request.set_interfaceid(machine_str);

		stub_->ListInterfacePrefixes(&context, request, &reply);
		if (reply.status().error())
			printf("Received an error %d\n", reply.status().error());
		else
			for (i = 0; i < reply.prefixes_size(); i++) {
				printf("Route prefix %s len %d underlayroute %s\n",
					reply.prefixes(i).address().c_str(),
					reply.prefixes(i).prefixlength(),
					reply.prefixes(i).underlayroute().c_str());
			}
	}

	void DelLBPfx() {
			DeleteInterfaceLoadBalancerPrefixRequest request;
			DeleteInterfaceLoadBalancerPrefixResponse reply;
			ClientContext context;
			Prefix *pfx_ip = new Prefix();

			request.set_interfaceid(machine_str);
			pfx_ip->set_ipversion(version);
			if(version == IPVersion::IPv4)
				pfx_ip->set_address(ip_str);
			pfx_ip->set_prefixlength(length);
			request.set_allocated_prefix(pfx_ip);
			stub_->DeleteInterfaceLoadBalancerPrefix(&context, request, &reply);
			if (reply.status().error())
				printf("Received an error %d\n", reply.status().error());
			else
				printf("LB prefix deleted\n");
	}

	void ListLBPfx() {
		ListInterfaceLoadBalancerPrefixesRequest request;
		ListInterfaceLoadBalancerPrefixesResponse reply;
		ClientContext context;
		int i;

		request.set_interfaceid(machine_str);

		stub_->ListInterfaceLoadBalancerPrefixes(&context, request, &reply);
		if (reply.status().error())
			printf("Received an error %d\n", reply.status().error());
		else
			for (i = 0; i < reply.prefixes_size(); i++) {
				printf("LB Route prefix %s len %d underlayroute %s\n",
					reply.prefixes(i).address().c_str(),
					reply.prefixes(i).prefixlength(),
					reply.prefixes(i).underlayroute().c_str());
			}
	}

	void DelVIP() {
			DeleteInterfaceVIPRequest request;
			DeleteInterfaceVIPResponse reply;
			ClientContext context;

			request.set_interfaceid(machine_str);
			stub_->DeleteInterfaceVIP(&context, request, &reply);
			if (reply.status().error())
				printf("Received an error %d\n", reply.status().error());
			else
				printf("VIP deleted\n");
	}

	void GetVIP() {
			GetInterfaceVIPRequest request;
			GetInterfaceVIPResponse reply;
			ClientContext context;

			request.set_interfaceid(machine_str);
			stub_->GetInterfaceVIP(&context, request, &reply);
			if (reply.status().error())
				printf("Received an error %d\n", reply.status().error());
			else
				printf("Received VIP %s underlayroute %s\n",
					   reply.interfacevipip().address().c_str(), reply.interfacevipip().underlayroute().c_str());
	}

	void DelInterface() {
			DeleteInterfaceRequest request;
			DeleteInterfaceResponse reply;
			ClientContext context;

			request.set_interfaceid(machine_str);
			stub_->DeleteInterface(&context, request, &reply);
			if (reply.status().error())
				printf("Received an error %d\n", reply.status().error());
			else
				printf("Interface deleted\n");
	}

	void GetInterface() {
			GetInterfaceRequest request;
			GetInterfaceResponse reply;
			ClientContext context;

			request.set_interfaceid(machine_str);
			stub_->GetInterface(&context, request, &reply);
			if (reply.status().error()) {
				printf("Received an error %d\n", reply.status().error());
			} else {
				printf("Interface with ipv4 %s ipv6 %s vni %d pci %s underlayroute %s\n",
				reply.interface().primaryipv4address().c_str(),
				reply.interface().primaryipv6address().c_str(),
				reply.interface().vni(),
				reply.interface().pcidpname().c_str(),
				reply.interface().underlayroute().c_str());
			}
	}

	void ListInterfaces() {
		ListInterfacesRequest request;
		ListInterfacesResponse reply;
		ClientContext context;
		int i;

		stub_->ListInterfaces(&context, request, &reply);
		if (reply.status().error())
			printf("Received an error %d\n", reply.status().error());
		else
			for (i = 0; i < reply.interfaces_size(); i++) {
				printf("Interface %s ipv4 %s ipv6 %s vni %d pci %s underlayroute %s\n", reply.interfaces(i).interfaceid().c_str(),
					reply.interfaces(i).primaryipv4address().c_str(),
					reply.interfaces(i).primaryipv6address().c_str(),
					reply.interfaces(i).vni(),
					reply.interfaces(i).pcidpname().c_str(),
					reply.interfaces(i).underlayroute().c_str());
			}
	}

	void CreateNAT() {
		CreateNATRequest request;
		CreateNATResponse reply;
		ClientContext context;
		NATIP *nat_vip = new NATIP();

		request.set_interfaceid(machine_str);
		nat_vip->set_ipversion(version);
		if(version == IPVersion::IPv4)
			nat_vip->set_address(ip_str);
		request.set_allocated_natvipip(nat_vip);
		request.set_minport(min_port);
		request.set_maxport(max_port);
		stub_->CreateNAT(&context, request, &reply);
		if (reply.status().error())
			printf("Received an error %d\n", reply.status().error());
		else
			printf("Received underlay route : %s\n", reply.underlayroute().c_str());
	}

	void DelNAT() {
		DeleteNATRequest request;
		DeleteNATResponse reply;
		ClientContext context;

		request.set_interfaceid(machine_str);
		stub_->DeleteNAT(&context, request, &reply);
		if (reply.status().error())
			printf("Received an error %d\n", reply.status().error());
		else
			printf("NAT deleted\n");
	}

	void GetNAT() {
		GetNATRequest request;
		GetNATResponse reply;
		ClientContext context;

		request.set_interfaceid(machine_str);
		stub_->GetNAT(&context, request, &reply);
		if (reply.status().error())
			printf("Received an error %d\n", reply.status().error());
		else
			printf("Received NAT IP %s with min port: %d and max port: %d underlay %s\n",
					reply.natvipip().address().c_str(), reply.minport(), reply.maxport(),
					reply.underlayroute().c_str());
	}

	void CreateNeighNAT() {
		CreateNeighborNATRequest request;
		CreateNeighborNATResponse reply;
		ClientContext context;
		NATIP *nat_vip = new NATIP();

		nat_vip->set_ipversion(version);
		if(version == IPVersion::IPv4) {
			nat_vip->set_address(ip_str);
		} else {
			nat_vip->set_address(ip6_str);
		}

		request.set_allocated_natvipip(nat_vip);
		request.set_vni(vni);
		request.set_minport(min_port);
		request.set_maxport(max_port);
		request.set_underlayroute(t_ip6_str);

		stub_->CreateNeighborNAT(&context, request, &reply);
		if (reply.status().error())
			printf("Received an error %d\n", reply.status().error());
		else
			printf("Neighbor NAT added\n");
	}

	void ListLocalNATs() {
		ListLocalNATsRequest request;
		ListLocalNATsResponse reply;
		ClientContext context;
		NATIP *nat_vip = new NATIP();
		int i;

		nat_vip->set_ipversion(version);
		if (version == IPVersion::IPv4)
			nat_vip->set_address(ip_str);
		else
			nat_vip->set_address(ip6_str);
		request.set_allocated_natvipip(nat_vip);

		stub_->ListLocalNATs(&context, request, &reply);
		if (reply.status().error())
			printf("Received an error %d\n", reply.status().error());
		else {
			printf("Following private IPs are NAT into this IPv4 NAT address: %s\n", nat_vip->address().c_str());
			for (i = 0; i < reply.natinfoentries_size(); i++) {
				printf("  %d: IP %s, min_port %u, max_port %u, vni: %u\n", i+1,
				reply.natinfoentries(i).address().c_str(),
				reply.natinfoentries(i).minport(),
				reply.natinfoentries(i).maxport(),
				reply.natinfoentries(i).vni());
			}
		}
	}
	void ListNeighNATs() {
		ListNeighborNATsRequest request;
		ListNeighborNATsResponse reply;
		ClientContext context;
		NATIP *nat_vip = new NATIP();
		int i;

		nat_vip->set_ipversion(version);
		if (version == IPVersion::IPv4)
			nat_vip->set_address(ip_str);
		else
			nat_vip->set_address(ip6_str);
		request.set_allocated_natvipip(nat_vip);

		stub_->ListNeighborNATs(&context, request, &reply);
		if (reply.status().error())
			printf("Received an error %d\n", reply.status().error());
		else {
			printf("Following port ranges and their route of neighbor NAT exists for this IPv4 NAT address: %s\n", nat_vip->address().c_str());
			for (i = 0; i < reply.natinfoentries_size(); i++) {
				printf("  %d: min_port %u, max_port %u, vni %u --> Underlay IPv6 %s\n", i+1,
				reply.natinfoentries(i).minport(),
				reply.natinfoentries(i).maxport(),
				reply.natinfoentries(i).vni(),
				reply.natinfoentries(i).underlayroute().c_str());
			}
		}
	}
	void GetNATInfo() {
		if (!strcmp(get_nat_info_type_str, "local"))
			ListLocalNATs();
		else if (!strcmp(get_nat_info_type_str, "neigh"))
			ListNeighNATs();
		else
			printf("Wrong query nat info type parameter, either local or neigh\n");
	}

	void DelNeighNAT() {
		DeleteNeighborNATRequest request;
		DeleteNeighborNATResponse reply;
		ClientContext context;
		NATIP *nat_vip = new NATIP();

		nat_vip->set_ipversion(version);
		if(version == IPVersion::IPv4) {
			nat_vip->set_address(ip_str);
		} else {
			nat_vip->set_address(ip6_str);
		}

		request.set_allocated_natvipip(nat_vip);
		request.set_vni(vni);
		request.set_minport(min_port);
		request.set_maxport(max_port);

		stub_->DeleteNeighborNAT(&context, request, &reply);
		if (reply.status().error())
			printf("Received an error %d\n", reply.status().error());
		else
			printf("Neighbor NAT deleted\n");
	}

	void GetVersion() {
		GetVersionRequest request;
		GetVersionResponse reply;
		ClientContext context;

		request.set_clientproto(DP_SERVICE_VERSION);
		request.set_clientname("dp_grpc_client");
		request.set_clientver(DP_SERVICE_VERSION);

		stub_->GetVersion(&context, request, &reply);
		if (reply.status().error())
			printf("Received an error %d\n", reply.status().error());
		else
			printf("Got protocol '%s' on service '%s'\n", reply.svcproto().c_str(), reply.svcver().c_str());
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
		dpdk_client.CreateVIP();
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
		dpdk_client.CreateNAT();
		break;
	case DP_CMD_GET_NAT_INFO:
		std::cout << "getNATEntry called " << std::endl;
		dpdk_client.GetNATInfo();
		break;
	case DP_CMD_DEL_NAT_VIP:
		std::cout << "Delnat called " << std::endl;
		dpdk_client.DelNAT();
		break;
	case DP_CMD_GET_NAT_VIP:
		std::cout << "Getnat called " << std::endl;
		dpdk_client.GetNAT();
		break;
	case DP_CMD_ADD_NEIGH_NAT:
		std::cout << "AddNeighNat called " << std::endl;
		dpdk_client.CreateNeighNAT();
		break;
	case DP_CMD_DEL_NEIGH_NAT:
		std::cout << "DelNeighNat called " << std::endl;
		dpdk_client.DelNeighNAT();
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
