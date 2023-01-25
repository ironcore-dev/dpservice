#include "dp_conf.h"

#include <stddef.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <net/if.h>
#include <arpa/inet.h>

#include "dp_error.h"
#include "dp_version.h"
#include "nodes/common_node.h"  // graphtrace level limit
#include "dpdk_layer.h"  // underlay conf struct

#define DP_CONF_DEFAULT_CONF_FILE "/tmp/dp_service.conf"

// magic number, hopefully large enough to hold the full '-a' EAL argument
#define DP_EAL_A_MAXLEN 128

// generated definitions for getopt(),
// generated storage variables and
// generated getters for such variables
#include "dp_conf_opts.c"

// custom storage variables and getters
struct dp_conf_dhcp_dns_private {
	int len;
	uint8_t *array;
};
static bool wcmp_enabled = false;
static char eal_a_pf0[DP_EAL_A_MAXLEN] = {0};
static char eal_a_pf1[DP_EAL_A_MAXLEN] = {0};
static struct dp_conf_dhcp_dns_private dhcp_dns = {0};

int dp_conf_is_wcmp_enabled()
{
	return wcmp_enabled;
}

const char *dp_conf_get_eal_a_pf0()
{
	return eal_a_pf0;
}

const char *dp_conf_get_eal_a_pf1()
{
	return eal_a_pf1;
}

const struct dp_conf_dhcp_dns *dp_conf_get_dhcp_dns()
{
	return (struct dp_conf_dhcp_dns *)&dhcp_dns;
}


static inline int opt_strcpy(char *dst, const char *src, size_t max_size)
{
	size_t len = strlen(src);

	if (len >= max_size) {
		fprintf(stderr, "Value '%s' is too long (max %lu characters)\n", src, max_size-1);
		return DP_ERROR;
	}

	memcpy(dst, src, len+1);  // including \0
	return DP_OK;
}

static inline int opt_str_to_int(int *dst, const char *src, int min, int max)
{
	long result;
	char *endptr;

	result = strtol(src, &endptr, 10);
	if (*endptr) {
		fprintf(stderr, "Value '%s' is not an integer\n", src);
		return DP_ERROR;
	}
	if (result < min || result > max) {
		fprintf(stderr, "Value '%s' is not in range %d-%d\n", src, min, max);
		return DP_ERROR;
	}

	*dst = (int)result;  // this is fine, limited by min/max
	return DP_OK;
}

static inline int opt_str_to_double(double *dst, const char *src, double min, double max)
{
	double result;
	char *endptr;

	result = strtod(src, &endptr);
	if (*endptr) {
		fprintf(stderr, "Value '%s' is not a double\n", src);
		return DP_ERROR;
	}
	if (result < min || result > max) {
		fprintf(stderr, "Value '%s' is not in range %lf-%lf\n", src, min, max);
		return DP_ERROR;
	}

	*dst = result;
	return DP_OK;
}

static int opt_str_to_ipv6(void *dst, const char *arg)
{
	if (inet_pton(AF_INET6, arg, dst) != 1) {
		fprintf(stderr, "Invalid IPv6 address format: '%s'\n", arg);
			return DP_ERROR;
	}
	return DP_OK;
}

static int opt_str_to_enum(int *dst, const char *arg, const char *choices[], uint choice_count)
{
	for (int i = 0; i < choice_count; ++i) {
		if (!strcmp(choices[i], arg)) {
			*dst = i;
			return DP_OK;
		}
	}
	fprintf(stderr, "Invalid choice '%s'\n", arg);
	return DP_ERROR;
}

static int add_dhcp_dns(const char *str)
{
	uint8_t *tmp;
	uint32_t ip;
	struct in_addr addr;

	if (inet_aton(str, &addr) != 1) {
		fprintf(stderr, "Invalid IPv4 address '%s'\n", str);
		return DP_ERROR;
	}

	// RFC 2132 - array length is stored in a byte
	if (dhcp_dns.len + 4 > UINT8_MAX) {
		fprintf(stderr, "Too many DHCP DNS addresses specified\n");
		return DP_ERROR;
	}

	tmp = (uint8_t *)realloc(dhcp_dns.array, dhcp_dns.len + 4);
	if (!tmp) {
		fprintf(stderr, "Cannot allocate memory for DNS address\n");
		return DP_ERROR;
	}
	dhcp_dns.array = tmp;

	ip = htonl(addr.s_addr);
	rte_memcpy(&dhcp_dns.array[dhcp_dns.len], &ip, sizeof(ip));
	dhcp_dns.len += 4;
	return DP_OK;
}

static int parse_opt(int opt, const char *arg)
{
	switch (opt) {
	case OPT_PF0:
		return opt_strcpy(pf0_name, arg, sizeof(pf0_name));
	case OPT_PF1:
		return opt_strcpy(pf1_name, arg, sizeof(pf1_name));
	case OPT_VF_PATTERN:
		return opt_strcpy(vf_pattern, arg, sizeof(vf_pattern));
	case OPT_IPV6:
		return opt_str_to_ipv6(get_underlay_conf()->src_ip6, arg);
	case OPT_OVERLAY_TYPE:
		return opt_str_to_enum((int *)&overlay_type, arg, overlay_type_choices, RTE_DIM(overlay_type_choices));
	case OPT_NIC_TYPE:
		return opt_str_to_enum((int *)&nic_type, arg, nic_type_choices, RTE_DIM(nic_type_choices));
	case OPT_DHCP_MTU:
		return opt_str_to_int(&dhcp_mtu, arg, 68, 1500);  // RFC 791, RFC 894
	case OPT_DHCP_DNS:
		return add_dhcp_dns(arg);
	case OPT_WCMP_FRACTION:
		wcmp_enabled = true;
		return opt_str_to_double(&wcmp_frac, arg, 0.0, 1.0);
	case OPT_NO_OFFLOAD:
		offload_enabled = false;
		return DP_OK;
	case OPT_NO_CONNTRACK:
		conntrack_enabled = false;
		return DP_OK;
	case OPT_NO_STATS:
		stats_enabled = false;
		return DP_OK;
	case OPT_ENABLE_IPV6_OVERLAY:
		ipv6_overlay_enabled = true;
		return DP_OK;
#ifdef ENABLE_GRAPHTRACE
	case OPT_GRAPHTRACE:
		return opt_str_to_int(&graphtrace_level, arg, 0, DP_GRAPHTRACE_LEVEL_MAX);
#endif
	case OPT_COLOR:
		return opt_str_to_enum((int *)&color, arg, color_choices, RTE_DIM(color_choices));
	default:
		fprintf(stderr, "Unimplemented option %d\n", opt);
		return DP_ERROR;
	}
}

static inline void print_usage(const char *progname, FILE *outfile)
{
	fprintf(outfile, "Usage: %s [EAL options] -- [service options]\n", progname);
	print_help_args(outfile);
}

enum dp_conf_runmode dp_conf_parse_args(int argc, char **argv)
{
	const char *progname = argv[0];
	int opt;

	while ((opt = getopt_long(argc, argv, OPTSTRING, longopts, NULL)) != -1) {
		switch (opt) {
		case OPT_HELP:
			print_usage(progname, stdout);
			return DP_CONF_RUNMODE_EXIT;
		case OPT_VERSION:
			printf("DP Service version %s\n", DP_SERVICE_VERSION);
			return DP_CONF_RUNMODE_EXIT;
		case '?':
			print_usage(progname, stderr);
			return DP_CONF_RUNMODE_ERROR;
		default:
			if (DP_FAILED(parse_opt(opt, optarg)))
				return DP_CONF_RUNMODE_ERROR;
		}
	}

	return DP_CONF_RUNMODE_NORMAL;
}


static const struct option *get_opt_by_name(const char *name)
{
	const struct option *longopt;

	for (longopt = longopts; longopt->name; ++longopt)
		if (!strcmp(name, longopt->name))
			return longopt;

	return NULL;
}

static int parse_line(char *line, int lineno)
{
	char *key;
	char *value;
	const struct option *longopt;

	// Ignore comments and empty lines
	if (*line == '#' || *line == '\n')
		return DP_OK;

	key = strtok(line, " \t\n");
	if (!key) {
		fprintf(stderr, "Config file error: no key on line %d\n", lineno);
		return DP_ERROR;
	}

	longopt = get_opt_by_name(key);

	value = strtok(NULL, " \t\n");
	if (!value && (!longopt || longopt->has_arg)) {
		fprintf(stderr, "Config file error: value required for key '%s' on line %d\n", key, lineno);
		return DP_ERROR;
	}

	// Config-file-specific keys
	if (!strcmp(key, "a-pf0"))
		return opt_strcpy(eal_a_pf0, value, sizeof(eal_a_pf0));
	if (!strcmp(key, "a-pf1"))
		return opt_strcpy(eal_a_pf1, value, sizeof(eal_a_pf1));

	// Otherwise support all long options
	if (!longopt) {
		fprintf(stderr, "Config file: unknown key '%s'\n", key);
		return DP_ERROR;
	}

	return parse_opt(longopt->val, value);
}

static int parse_file(FILE *file)
{
	char *line = NULL;
	size_t linesize = 0;
	ssize_t linelen;
	int lineno = 0;
	int ret = DP_OK;

	while ((linelen = getline(&line, &linesize, file)) > 0) {
		ret = parse_line(line, lineno);
		if (DP_FAILED(ret))
			break;
		lineno++;
	}

	free(line);
	return ret;
}

int dp_conf_parse_file(const char *env_filename)
{
	int ret;
	FILE *file;
	const char *filename = env_filename ? env_filename : DP_CONF_DEFAULT_CONF_FILE;

	file = fopen(filename, "r");
	if (!file) {
		// do not warn about the default file (optional to use)
		// also empty value can be provided used on purpose (to disable its use)
		if (!env_filename || !*filename)
			return DP_OK;
		fprintf(stderr, "Error opening config file '%s'\n", filename);
		return DP_ERROR;
	}

	ret = parse_file(file);

	fclose(file);
	return ret;
}

void dp_conf_free()
{
	free(dhcp_dns.array);
}
