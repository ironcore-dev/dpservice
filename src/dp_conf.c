#include "dp_conf.h"

#include <stddef.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <net/if.h>
#include <arpa/inet.h>

#include "dp_error.h"
#include "dp_flow.h"
#include "dp_log.h"
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
static bool wcmp_enabled = false;
static char eal_a_pf0[DP_EAL_A_MAXLEN] = {0};
static char eal_a_pf1[DP_EAL_A_MAXLEN] = {0};
static struct dp_conf_dhcp_dns dhcp_dns = {0};
#ifdef ENABLE_VIRTSVC
static struct dp_conf_virtual_services virtual_services = {0};
#endif

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
	return &dhcp_dns;
}

#ifdef ENABLE_VIRTSVC
const struct dp_conf_virtual_services *dp_conf_get_virtual_services()
{
	return &virtual_services;
}
#endif


static inline int opt_strcpy(char *dst, const char *src, size_t max_size)
{
	size_t len = strlen(src);

	if (len >= max_size) {
		DP_EARLY_ERR("Value '%s' is too long (max %lu characters)", src, max_size-1);
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
		DP_EARLY_ERR("Value '%s' is not an integer", src);
		return DP_ERROR;
	}
	if (result < min || result > max) {
		DP_EARLY_ERR("Value '%s' is not in range %d-%d", src, min, max);
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
		DP_EARLY_ERR("Value '%s' is not a double", src);
		return DP_ERROR;
	}
	if (result < min || result > max) {
		DP_EARLY_ERR("Value '%s' is not in range %lf-%lf", src, min, max);
		return DP_ERROR;
	}

	*dst = result;
	return DP_OK;
}

static int opt_str_to_ipv6(void *dst, const char *arg)
{
	if (inet_pton(AF_INET6, arg, dst) != 1) {
		DP_EARLY_ERR("Invalid IPv6 address format: '%s'", arg);
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
	DP_EARLY_ERR("Invalid choice '%s'", arg);
	return DP_ERROR;
}

static int add_dhcp_dns(const char *str)
{
	uint8_t *tmp;
	struct in_addr addr;

	if (inet_aton(str, &addr) != 1) {
		DP_EARLY_ERR("Invalid IPv4 address '%s'", str);
		return DP_ERROR;
	}

	// RFC 2132 - array length is stored in a byte
	if (dhcp_dns.len + 4 > UINT8_MAX) {
		DP_EARLY_ERR("Too many DHCP DNS addresses specified");
		return DP_ERROR;
	}

	tmp = (uint8_t *)realloc(dhcp_dns.array, dhcp_dns.len + 4);
	if (!tmp) {
		DP_EARLY_ERR("Cannot allocate memory for DNS address");
		return DP_ERROR;
	}
	dhcp_dns.array = tmp;

	rte_memcpy(&dhcp_dns.array[dhcp_dns.len], &addr.s_addr, sizeof(addr.s_addr));
	dhcp_dns.len += 4;
	return DP_OK;
}

#ifdef ENABLE_VIRTSVC
static int add_virtsvc(uint16_t proto, const char *str)
{
	struct dp_conf_virtsvc *tmp;
	unsigned long longport;
	struct in_addr from_addr;
	rte_be16_t from_port;
	struct in6_addr to_addr;
	rte_be16_t to_port;
	char parse_str[256];  // more than enough to hold a valid quadruple
	char *tok;
	char *endptr;

	if (virtual_services.nb_entries >= DP_VIRTSVC_MAX) {
		DP_EARLY_ERR("Number of virtual services is limited to %u", DP_VIRTSVC_MAX);
		return DP_ERROR;
	}

	// strtok() is destructive, make a copy
	snprintf(parse_str, sizeof(parse_str), "%s", str);

	tok = strtok(parse_str, ",");
	if (!tok) {
		DP_EARLY_ERR("Missing virtual service IPv4");
		return DP_ERROR;
	}
	if (inet_aton(tok, &from_addr) != 1) {
		DP_EARLY_ERR("Invalid virtual service IPv4 address '%s'", tok);
		return DP_ERROR;
	}

	tok = strtok(NULL, ",");
	if (!tok) {
		DP_EARLY_ERR("Missing virtual service IPv4 port");
		return DP_ERROR;
	}
	longport = strtoul(tok, &endptr, 10);
	if (!*tok || *endptr || !longport || longport > UINT16_MAX) {
		DP_EARLY_ERR("Invalid virtual service IPv4 port '%s'", tok);
		return DP_ERROR;
	}
	from_port = htons(longport);

	tok = strtok(NULL, ",");
	if (!tok) {
		DP_EARLY_ERR("Missing virtual service IPv6");
		return DP_ERROR;
	}
	if (inet_pton(AF_INET6, tok, &to_addr) != 1) {
		DP_EARLY_ERR("Invalid virtual service IPv6 address '%s'", tok);
		return DP_ERROR;
	}

	tok = strtok(NULL, ",");
	if (!tok) {
		DP_EARLY_ERR("Missing virtual service IPv6 port");
		return DP_ERROR;
	}
	longport = strtoul(tok, &endptr, 10);
	if (!*tok || *endptr || !longport || longport > UINT16_MAX) {
		DP_EARLY_ERR("Invalid virtual service IPv6 port '%s'", tok);
		return DP_ERROR;
	}
	to_port = htons(longport);

	// prevent virtual/service address duplicates
	for (int i = 0; i < virtual_services.nb_entries; ++i) {
		tmp = &virtual_services.entries[i];
		if (tmp->proto == proto) {
			if (tmp->virtual_addr == from_addr.s_addr && tmp->virtual_port == from_port) {
				DP_EARLY_ERR("IPv4 specification already used for '%s'", str);
				return DP_ERROR;
			} else if (!memcmp(&tmp->service_addr, &to_addr, sizeof(to_addr)) && tmp->service_port == to_port) {
				DP_EARLY_ERR("IPv6 specification already used for '%s'", str);
				return DP_ERROR;
			}
		}
	}

	tmp = (struct dp_conf_virtsvc *)realloc(virtual_services.entries,
											(virtual_services.nb_entries + 1) * sizeof(struct dp_conf_virtsvc));
	if (!tmp) {
		DP_EARLY_ERR("Cannot allocate memory for virtual service");
		return DP_ERROR;
	}
	virtual_services.entries = tmp;

	tmp += virtual_services.nb_entries;
	tmp->proto = proto;
	tmp->virtual_addr = from_addr.s_addr;
	tmp->virtual_port = from_port;
	rte_memcpy(&tmp->service_addr, &to_addr, sizeof(to_addr));
	tmp->service_port = to_port;
	virtual_services.nb_entries++;
	return DP_OK;
}
#endif

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
	case OPT_NIC_TYPE:
		return opt_str_to_enum((int *)&nic_type, arg, nic_type_choices, RTE_DIM(nic_type_choices));
	case OPT_DHCP_MTU:
		return opt_str_to_int(&dhcp_mtu, arg, 68, 1500);  // RFC 791, RFC 894
	case OPT_DHCP_DNS:
		return add_dhcp_dns(arg);
#ifdef ENABLE_VIRTSVC
	case OPT_TCP_VIRTSVC:
		return add_virtsvc(IPPROTO_TCP, arg);
	case OPT_UDP_VIRTSVC:
		return add_virtsvc(IPPROTO_UDP, arg);
#endif
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
#ifdef ENABLE_PYTEST
	case OPT_GRAPHTRACE_LOGLEVEL:
		return opt_str_to_int(&graphtrace_loglevel, arg, 0, DP_GRAPHTRACE_LOGLEVEL_MAX);
#endif
#endif
	case OPT_COLOR:
		return opt_str_to_enum((int *)&color, arg, color_choices, RTE_DIM(color_choices));
	case OPT_LOG_FORMAT:
		return opt_str_to_enum((int *)&log_format, arg, log_format_choices, RTE_DIM(log_format_choices));
	case OPT_GRPC_PORT:
		return opt_str_to_int(&grpc_port, arg, 1024, 65535);
#ifdef ENABLE_PYTEST
	case OPT_FLOW_TIMEOUT:
		return opt_str_to_int((int *)&flow_timeout, arg, 1, 300);
#endif
	default:
		DP_EARLY_ERR("Unimplemented option %d", opt);
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
		DP_EARLY_ERR("Config file error: no key on line %d", lineno);
		return DP_ERROR;
	}

	longopt = get_opt_by_name(key);

	value = strtok(NULL, " \t\n");
	if (!value && (!longopt || longopt->has_arg)) {
		DP_EARLY_ERR("Config file error: value required for key '%s' on line %d", key, lineno);
		return DP_ERROR;
	}

	// Config-file-specific keys
	if (!strcmp(key, "a-pf0"))
		return opt_strcpy(eal_a_pf0, value, sizeof(eal_a_pf0));
	if (!strcmp(key, "a-pf1"))
		return opt_strcpy(eal_a_pf1, value, sizeof(eal_a_pf1));

	// Otherwise support all long options
	if (!longopt) {
		DP_EARLY_ERR("Config file: unknown key '%s'", key);
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
		DP_EARLY_ERR("Error opening config file '%s'", filename);
		return DP_ERROR;
	}

	ret = parse_file(file);

	fclose(file);
	return ret;
}

void dp_conf_free()
{
	free(dhcp_dns.array);
#ifdef ENABLE_VIRTSVC
	free(virtual_services.entries);
#endif
}
