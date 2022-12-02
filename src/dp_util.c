#include <getopt.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <net/if.h>
#include "rte_ip.h"
#include "dp_util.h"
#include "dpdk_layer.h"
#include "rte_flow/dp_rte_flow.h"

#define DP_MAX_IP6_CHAR 40
#define DP_MAX_VNI_STR 12
#define DP_TUNNEL_OPT_SIZE 8
#define DP_OP_ENV_OPT_SIZE 10
#define DP_CONF_FILE_SIZE 64
#define DP_LINE_SIZE 128
#define DP_WCMP_FRAC_SIZE 5
#define DP_A_OPT_SIZE 80 /* Mellanox driver -a option */

static bool conf_file_info_printed = false;
static int debug_mode = 0;
static int no_offload = 0;
static int ipv6_overlay = 0;
static int no_conntrack = 0;
static int no_stats = 0;
static int no_hw_protection = 0;
static int tunnel_opt = DP_FLOW_OVERLAY_TYPE_IPIP;
static int op_env = DP_OP_ENV_HARDWARE;
static double wcmp_frac = 1.0;
static int wcmp_enabled = 0;
static char pf0name[IF_NAMESIZE] = {0};
static char pf1name[IF_NAMESIZE] = {0};
static char pf0_a[DP_A_OPT_SIZE] = {0};
static char pf1_a[DP_A_OPT_SIZE] = {0};
static char vf_pattern[IF_NAMESIZE] = {0};
static char ip6_str[DP_MAX_IP6_CHAR] = {0};
static char vni_str[DP_MAX_IP6_CHAR] = {0};
static uint16_t pf_ports[DP_MAX_PF_PORT][2] = {0};
static char tunnel_opt_str[DP_TUNNEL_OPT_SIZE] = {0};
static char op_env_opt_str[DP_OP_ENV_OPT_SIZE] = {0};
static char conf_file_str[DP_CONF_FILE_SIZE] = {0};
static char wcmp_frac_opt_str[DP_WCMP_FRAC_SIZE] = {0};
static int graphtrace_level = 0;

// TODO(plague): merge with long and use getsubopt()
static const char short_options[] = "d" /* debug */
									"D" /* promiscuous */;
static const char tunnel_opt_geneve[] = "geneve";
static const char op_env_opt_scapytest[] = "scapytest";

#define DP_SYSFS_PREFIX_MLX_VF_COUNT	"/sys/class/net/"
#define DP_SYSFS_SUFFIX_MLX_VF_COUNT	"/device/sriov_numvfs"
#define DP_DEFAULT_CONF_FILE			"/tmp/dp_service.conf"
#define DP_SYSFS_STR_LEN 256

#define CMD_LINE_OPT_PF0 "pf0"
#define CMD_LINE_OPT_PF1 "pf1"
#define CMD_LINE_OPT_PF0_A "a-pf0"
#define CMD_LINE_OPT_PF1_A "a-pf1"
#define CMD_LINE_OPT_IPV6 "ipv6"
#define CMD_LINE_OPT_VF_PATTERN "vf-pattern"
#define CMD_LINE_OPT_TUN_OPT "tun_opt"
#define CMD_LINE_OPT_CONF_FILE "conf-file"
#define CMD_LINE_OPT_OP_ENV "op_env"
#define CMD_LINE_OPT_VNI "vni"
#define CMD_LINE_OPT_NO_OFFLOAD "no-offload"
#define CMD_LINE_OPT_ENABLE_IPV6_OVERLAY "enable-ipv6-overlay"
#define CMD_LINE_OPT_NO_CONNTRACK "no-conntrack"
#define CMD_LINE_OPT_NO_STATS "no-stats"
#define CMD_LINE_OPT_WCMP_FRAC "wcmp-frac"
#ifdef ENABLE_GRAPHTRACE
#	define CMD_LINE_OPT_GRAPHTRACE "graphtrace"
#endif
#define CMD_LINE_OPT_NO_HW_PROTECT "no-hw-protect"

enum
{
	CMD_LINE_OPT_MIN_NUM = 256,
	CMD_LINE_OPT_PF0_NUM,
	CMD_LINE_OPT_PF1_NUM,
	CMD_LINE_OPT_IPV6_NUM,
	CMD_LINE_OPT_VF_PATTERN_NUM,
	CMD_LINE_OPT_TUN_OPT_NUM,
	CMD_LINE_OPT_OP_ENV_NUM,
	CMD_LINE_OPT_VNI_NUM,
	CMD_LINE_OPT_NO_OFFLOAD_NUM,
	CMD_LINE_OPT_NO_CONNTRACK_NUM,
	CMD_LINE_OPT_NO_STATS_NUM,
	CMD_LINE_OPT_CONF_FILE_NUM,
	CMD_LINE_OPT_WCMP_FRAC_NUM,
	CMD_LINE_OPT_ENABLE_IPV6_OVERLAY_NUM,
#ifdef ENABLE_GRAPHTRACE
	CMD_LINE_OPT_GRAPHTRACE_NUM,
#endif
	CMD_LINE_OPT_IPV6_OVERLAY_NUM,
	CMD_LINE_OPT_NO_HW_PROTECT_NUM,
};

static const struct option lgopts[] = {
	{CMD_LINE_OPT_PF0, 1, 0, CMD_LINE_OPT_PF0_NUM},
	{CMD_LINE_OPT_PF1, 1, 0, CMD_LINE_OPT_PF1_NUM},
	{CMD_LINE_OPT_IPV6, 1, 0, CMD_LINE_OPT_IPV6_NUM},
	{CMD_LINE_OPT_VF_PATTERN, 1, 0, CMD_LINE_OPT_VF_PATTERN_NUM},
	{CMD_LINE_OPT_TUN_OPT, 1, 0, CMD_LINE_OPT_TUN_OPT_NUM},
	{CMD_LINE_OPT_OP_ENV, 1, 0, CMD_LINE_OPT_OP_ENV_NUM},
	{CMD_LINE_OPT_VNI, 1, 0, CMD_LINE_OPT_VNI_NUM},
	{CMD_LINE_OPT_WCMP_FRAC, 1, 0, CMD_LINE_OPT_WCMP_FRAC_NUM},
	{CMD_LINE_OPT_NO_OFFLOAD, 0, 0, CMD_LINE_OPT_NO_OFFLOAD_NUM},
	{CMD_LINE_OPT_ENABLE_IPV6_OVERLAY, 0, 0, CMD_LINE_OPT_ENABLE_IPV6_OVERLAY_NUM},
	{CMD_LINE_OPT_NO_CONNTRACK, 0, 0, CMD_LINE_OPT_NO_CONNTRACK_NUM},
	{CMD_LINE_OPT_NO_STATS, 0, 0, CMD_LINE_OPT_NO_STATS_NUM},
	{CMD_LINE_OPT_CONF_FILE, 1, 0, CMD_LINE_OPT_CONF_FILE_NUM},
#ifdef ENABLE_GRAPHTRACE
	{CMD_LINE_OPT_GRAPHTRACE, 1, 0, CMD_LINE_OPT_GRAPHTRACE_NUM},
#endif
	{CMD_LINE_OPT_NO_HW_PROTECT, 0, 0, CMD_LINE_OPT_NO_HW_PROTECT_NUM},
	{NULL, 0, 0, 0},
};

/* Display usage */
static void dp_print_usage(const char *prgname)
{
	fprintf(stderr,
			"%s [EAL options] -- [service options]\n"
			"  -d, -D                                enable debugmode\n"
			"  --"CMD_LINE_OPT_PF0"=IFNAME           name of first physical interface (e.g. eth0)\n"
			"  --"CMD_LINE_OPT_PF1"=IFNAME           name of second physical interface (e.g. eth1)\n"
			"  --"CMD_LINE_OPT_IPV6"=ADDR6           IPv6 underlay address\n"
			"  --"CMD_LINE_OPT_VF_PATTERN"=PATTERN   virtual interface name pattern (e.g. 'eth1vf')\n"
			"  --"CMD_LINE_OPT_TUN_OPT"=TUNTYPE      tunnel type to use ('ipip' or 'geneve'; default: 'ipip')\n"
			"  --"CMD_LINE_OPT_WCMP_FRAC"=FRACTION   wighted-cost-multipath fraction (0.0 - 1.0)\n"
			"  --"CMD_LINE_OPT_OP_ENV"=ENVTYPE       environment type to use ('scapytest' or 'hardware'; default: 'hardware')\n"
			"  --"CMD_LINE_OPT_VNI"=NUMBER           virtual network identifier to use\n"
			"  --"CMD_LINE_OPT_CONF_FILE"=PATH       config file to load (default: '/tmp/dp_service.conf')\n"
			"  --"CMD_LINE_OPT_NO_STATS"             do not print statistics to stdout\n"
			"  --"CMD_LINE_OPT_NO_CONNTRACK"         disable connection tracking\n"
			"  --"CMD_LINE_OPT_ENABLE_IPV6_OVERLAY"  enable IPv6 overlay addresses\n"
			"  --"CMD_LINE_OPT_NO_OFFLOAD"           disable traffic offloading\n"
			"  --"CMD_LINE_OPT_NO_HW_PROTECT"        disable hw protection for unknown incoming traffic\n"
#ifdef ENABLE_GRAPHTRACE
			"  --"CMD_LINE_OPT_GRAPHTRACE"=LEVEL     verbosity level of packet traversing the graph framework (default: 0)\n"
#endif
			"\n",
			prgname);
}

void dp_handle_conf_file()
{
	char s[DP_LINE_SIZE] = {0};
	FILE * fp;
	char * line = NULL;
	size_t len = 0, count = 0;
	ssize_t read;
	char* token;

	strncpy(conf_file_str, DP_DEFAULT_CONF_FILE, DP_CONF_FILE_SIZE - 1);
	fp = fopen(conf_file_str, "r");
	if (fp == NULL)
		return;

	while ((read = getline(&line, &len, fp)) != -1) {
		line[read-1] = '\0';
		strncpy(s, line, ((read > DP_LINE_SIZE) ? DP_LINE_SIZE : read));
		token = strtok(s, " ");
		if (strncmp(token, CMD_LINE_OPT_PF0, strlen(CMD_LINE_OPT_PF0)) == 0) {
			token = strtok(NULL, " ");
			strncpy(pf0name, token, IFNAMSIZ - 1);
			count++;
		}
		if (strncmp(token, CMD_LINE_OPT_PF1, strlen(CMD_LINE_OPT_PF1)) == 0) {
			token = strtok(NULL, " ");
			strncpy(pf1name, token, IFNAMSIZ - 1);
			count++;
		}
		if (strncmp(token, CMD_LINE_OPT_PF0_A, strlen(CMD_LINE_OPT_PF0_A)) == 0) {
			token = strtok(NULL, " ");
			strncpy(pf0_a, token, DP_A_OPT_SIZE - 1);
			count++;
		}
		if (strncmp(token, CMD_LINE_OPT_PF1_A, strlen(CMD_LINE_OPT_PF1_A)) == 0) {
			token = strtok(NULL, " ");
			strncpy(pf1_a, token, DP_A_OPT_SIZE - 1);
			count++;
		}
		if (strncmp(token, CMD_LINE_OPT_VF_PATTERN, strlen(CMD_LINE_OPT_VF_PATTERN)) == 0) {
			token = strtok(NULL, " ");
			strncpy(vf_pattern, token, IFNAMSIZ - 1);
			count++;
		}
		if (strncmp(token, CMD_LINE_OPT_IPV6, strlen(CMD_LINE_OPT_IPV6)) == 0) {
			token = strtok(NULL, " ");
			strncpy(ip6_str, token, DP_MAX_IP6_CHAR - 1);
			inet_pton(AF_INET6, ip6_str, get_underlay_conf()->src_ip6);
			count++;
		}
		/* Each line has only 2 tokens, otherwise file is corrupt */
		if (count != 1)
			return;
		count = 0;
	}

	if (!conf_file_info_printed) {
		conf_file_info_printed = true;
		printf("Config file found at %s and will be used ! \n", conf_file_str);
	}
	fclose(fp);
	free(line);
}

int dp_parse_args(int argc, char **argv)
{
	char *prgname = argv[0];
	int option_index;
	char **argvopt;
	int opt, ret, temp;

	argvopt = argv;

	/* Error or normal output strings. */
	while ((opt = getopt_long(argc, argvopt, short_options, lgopts,
							  &option_index)) != EOF)
	{

		switch (opt)
		{
			// TODO add --help
		case 'd':
		/* Intended fallthrough */
		case 'D':
			debug_mode = 1;
			break;

		/* Long options */
		case CMD_LINE_OPT_PF0_NUM:
			strncpy(pf0name, optarg, IFNAMSIZ - 1);
			break;

		case CMD_LINE_OPT_PF1_NUM:
			strncpy(pf1name, optarg, IFNAMSIZ - 1);
			break;

		case CMD_LINE_OPT_IPV6_NUM:
			strncpy(ip6_str, optarg, DP_MAX_IP6_CHAR - 1);
			inet_pton(AF_INET6, ip6_str, get_underlay_conf()->src_ip6);
			break;

		case CMD_LINE_OPT_VF_PATTERN_NUM:
			strncpy(vf_pattern, optarg, IFNAMSIZ - 1);
			break;
		case CMD_LINE_OPT_TUN_OPT_NUM:
			strncpy(tunnel_opt_str, optarg, DP_TUNNEL_OPT_SIZE - 1);
			if (!strcmp(tunnel_opt_str, tunnel_opt_geneve))
			{
				tunnel_opt = DP_FLOW_OVERLAY_TYPE_GENEVE;
			}
			else
			{
				tunnel_opt = DP_FLOW_OVERLAY_TYPE_IPIP;
			}

			break;
		case CMD_LINE_OPT_CONF_FILE_NUM:
			strncpy(conf_file_str, optarg, DP_CONF_FILE_SIZE- 1);
			break;
		

		case CMD_LINE_OPT_OP_ENV_NUM:
			strncpy(op_env_opt_str, optarg, DP_OP_ENV_OPT_SIZE - 1);
			if (!strcmp(op_env_opt_str, op_env_opt_scapytest))
			{
				op_env = DP_OP_ENV_SCAPYTEST;
			}
			else
			{
				op_env = DP_OP_ENV_HARDWARE;
			}

			break;

		case CMD_LINE_OPT_VNI_NUM:
			strncpy(vni_str, optarg, DP_MAX_VNI_STR - 1);
			temp = atoi(vni_str);
			memcpy(get_underlay_conf()->vni, &temp, sizeof(get_underlay_conf()->vni));
			break;

		case CMD_LINE_OPT_WCMP_FRAC_NUM:
			strncpy(wcmp_frac_opt_str, optarg, DP_WCMP_FRAC_SIZE - 1);
			wcmp_enabled = 1;
			wcmp_frac = strtod(wcmp_frac_opt_str, NULL);
			break;

		case CMD_LINE_OPT_NO_OFFLOAD_NUM:
			no_offload = 1;
			break;
		case CMD_LINE_OPT_ENABLE_IPV6_OVERLAY_NUM:
			ipv6_overlay = 1;
			break;
		case CMD_LINE_OPT_NO_CONNTRACK_NUM:
			no_conntrack = 1;
			break;
		case CMD_LINE_OPT_NO_HW_PROTECT_NUM:
			no_hw_protection = 1;
			break;
		case CMD_LINE_OPT_NO_STATS_NUM:
			no_stats = 1;
			break;
#ifdef ENABLE_GRAPHTRACE
		case CMD_LINE_OPT_GRAPHTRACE_NUM:
			graphtrace_level = atoi(optarg);
			break;
#endif
		default:
			dp_print_usage(prgname);
			return -1;
		}
	}

	if (optind >= 0)
		argv[optind - 1] = prgname;
	ret = optind - 1;
	optind = 1; /* Reset getopt lib */

	/* If conf file exists, overwrite some part of the settings from file */
	dp_handle_conf_file();

	return ret;
}

uint dp_get_graphtrace_level()
{
	return graphtrace_level;
}

int dp_is_offload_enabled()
{
	if (no_offload)
		return 0;
	else
		return 1;
}

int dp_is_hw_protection_enabled()
{
	if (no_hw_protection)
		return 0;
	else
		return 1;
}

int dp_is_conntrack_enabled()
{
	if (no_conntrack)
		return 0;
	else
		return 1;
}

int dp_is_ip6_overlay_enabled()
{
	if (ipv6_overlay)
		return 1;
	else
		return 0;
}

int get_overlay_type()
{
	return tunnel_opt;
}

int get_op_env()
{
	return op_env;
}

int dp_is_wcmp_enabled()
{
	return wcmp_enabled;
}

double dp_get_wcmp_frac()
{
	return wcmp_frac;
}

int dp_is_stats_enabled()
{
	if (no_stats)
		return 0;
	else
		return 1;
}

char *dp_get_pf0_name()
{
	return pf0name;
}

char *dp_get_pf1_name()
{
	return pf1name;
}

char *dp_get_pf0_opt_a()
{
	return pf0_a;
}

char *dp_get_pf1_opt_a()
{
	return pf1_a;
}

bool dp_is_mellanox_opt_set() 
{
	if (pf0_a[0] != '\0' && pf1_a[0] != '\0')
		return true;
	else
		return false;
}

char *dp_get_vf_pattern()
{
	return vf_pattern;
}

void dp_add_pf_port_id(uint16_t id)
{
	int i;

	for (i = 0; i < DP_MAX_PF_PORT; i++)
		if (!pf_ports[i][1])
		{
			pf_ports[i][0] = id;
			pf_ports[i][1] = 1;
			return;
		}
}

int dp_get_num_of_vfs()
{
	int ret = DP_ACTIVE_VF_PORT; /* Default value */
	char *filename;
	FILE *fp;

	filename = malloc(DP_SYSFS_STR_LEN);

	if (!filename)
		goto out;

	snprintf(filename, DP_SYSFS_STR_LEN, "%s%s%s", DP_SYSFS_PREFIX_MLX_VF_COUNT,
			 dp_get_pf0_name(), DP_SYSFS_SUFFIX_MLX_VF_COUNT);

	fp = fopen(filename, "r");

	if (!fp)
		goto err;

	fscanf(fp, "%d", &ret);

	fclose(fp);
err:
	free(filename);
out:
	return ret;
}

__rte_always_inline bool dp_is_pf_port_id(uint16_t id)
{
	int i;

	for (i = 0; i < DP_MAX_PF_PORT; i++)
		if (pf_ports[i][1] && (pf_ports[i][0] == id))
			return true;
	return false;
}

__rte_always_inline uint16_t dp_get_pf0_port_id()
{
	return pf_ports[0][0];
}

__rte_always_inline uint16_t dp_get_pf1_port_id()
{
	return pf_ports[1][0];
}

void rewrite_eth_hdr(struct rte_mbuf *m, uint16_t port_id, uint16_t eth_type)
{
	struct rte_ether_hdr *eth_hdr;

	eth_hdr = (struct rte_ether_hdr *)rte_pktmbuf_prepend(m, sizeof(struct rte_ether_hdr));
	rte_ether_addr_copy(dp_get_neigh_mac(port_id), &eth_hdr->dst_addr);
	eth_hdr->ether_type = htons(eth_type);
	rte_ether_addr_copy(dp_get_mac(port_id), &eth_hdr->src_addr);
}


void print_ip(unsigned int ip, char *buf)
{
    unsigned char bytes[4];
    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;  
    snprintf(buf, 18, "%d.%d.%d.%d", bytes[3], bytes[2], bytes[1], bytes[0]);        
}