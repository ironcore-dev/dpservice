#include <getopt.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <net/if.h>
#include "rte_ip.h"
#include "dp_util.h"
#include "dpdk_layer.h"

#define DP_MAX_IP6_CHAR	40
#define DP_MAX_VNI_STR	12

static int debug_mode = 0;
static int no_offload = 0;
static int no_stats = 0;
static char pf0name[IF_NAMESIZE] = {0};
static char pf1name[IF_NAMESIZE] = {0};
static char ip6_str[DP_MAX_IP6_CHAR] = {0};
static char vni_str[DP_MAX_IP6_CHAR] = {0};

static const char short_options[] = "d" /* debug */
				    "D"	 /* promiscuous */;

#define CMD_LINE_OPT_PF0		"pf0"
#define CMD_LINE_OPT_PF1		"pf1"
#define CMD_LINE_OPT_IPV6		"ipv6"
#define CMD_LINE_OPT_T_IPV6		"t_ipv6"
#define CMD_LINE_OPT_VNI		"vni"
#define CMD_LINE_OPT_NO_OFFLOAD	"no-offload"
#define CMD_LINE_OPT_NO_STATS	"no-stats"

enum {
	CMD_LINE_OPT_MIN_NUM = 256,
	CMD_LINE_OPT_PF0_NUM,
	CMD_LINE_OPT_PF1_NUM,
	CMD_LINE_OPT_IPV6_NUM,
	CMD_LINE_OPT_T_IPV6_NUM,
	CMD_LINE_OPT_VNI_NUM,
	CMD_LINE_OPT_NO_OFFLOAD_NUM,
	CMD_LINE_OPT_NO_STATS_NUM,
};

static const struct option lgopts[] = {
	{CMD_LINE_OPT_PF0, 1, 0, CMD_LINE_OPT_PF0_NUM},
	{CMD_LINE_OPT_PF1, 1, 0, CMD_LINE_OPT_PF1_NUM},
	{CMD_LINE_OPT_IPV6, 1, 0, CMD_LINE_OPT_IPV6_NUM},
	{CMD_LINE_OPT_T_IPV6, 0, 0, CMD_LINE_OPT_T_IPV6_NUM},
	{CMD_LINE_OPT_VNI, 0, 0, CMD_LINE_OPT_VNI_NUM},
	{CMD_LINE_OPT_NO_OFFLOAD, 0, 0, CMD_LINE_OPT_NO_OFFLOAD_NUM},
	{CMD_LINE_OPT_NO_STATS, 0, 0, CMD_LINE_OPT_NO_STATS_NUM},
	{NULL, 0, 0, 0},
};


/* Display usage */
static void dp_print_usage(const char *prgname)
{
	fprintf(stderr,
		"%s [EAL options] --"
		" -d"
		" [-D]"
		" --pf0=pf0_ifname"
		" --pf0=pf0_ifname"
		" --ipv6=underlay_ipv6"
		" --t_ipv6=target_ipv6"
		" --vni=vnet_id"
		" [--no-stats]"
		" [--no-offload]\n",
		prgname);
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
				  &option_index)) != EOF) {

		switch (opt) {
		case 'd':
		/* Intended fallthrough */
		case 'D':
			debug_mode = 1;
			break;

		/* Long options */
		case CMD_LINE_OPT_PF0_NUM:
			strncpy(pf0name, optarg, IFNAMSIZ);
			break;

		case CMD_LINE_OPT_PF1_NUM:
			strncpy(pf1name, optarg, IFNAMSIZ);
			break;

		case CMD_LINE_OPT_IPV6_NUM:
			strncpy(ip6_str, optarg, DP_MAX_IP6_CHAR - 1);
			inet_pton(AF_INET6, ip6_str, get_underlay_conf()->src_ip6);
			break;

		case CMD_LINE_OPT_T_IPV6_NUM:
			strncpy(ip6_str, optarg, DP_MAX_IP6_CHAR - 1);
			inet_pton(AF_INET6, ip6_str, get_underlay_conf()->trgt_ip6);
			break;

		case CMD_LINE_OPT_VNI_NUM:
			strncpy(vni_str, optarg, DP_MAX_VNI_STR - 1);
			temp = atoi(vni_str);
			memcpy(get_underlay_conf()->vni, &temp, sizeof(get_underlay_conf()->vni));
			break;

		case CMD_LINE_OPT_NO_OFFLOAD_NUM:
			no_offload = 1;
			break;

		case CMD_LINE_OPT_NO_STATS_NUM:
			no_stats = 1;
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

int dp_is_offload_enabled()
{
	if (no_offload)
		return 0;
	else
		return 1;
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