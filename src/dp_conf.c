// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

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

#define DP_CONF_DEFAULT_CONF_FILE "/run/dpservice/dpservice.conf"

// magic number, hopefully large enough to hold the full '-a' EAL argument
#define DP_EAL_A_MAXLEN 128

// generated definitions for getopt(),
// generated storage variables and
// generated getters for such variables
#include "dp_conf_opts.c"

// custom storage variables and getters
static char eal_a_pf0[DP_EAL_A_MAXLEN] = {0};
static char eal_a_pf1[DP_EAL_A_MAXLEN] = {0};
static union dp_ipv6 underlay_ip = {0};
static struct dp_conf_dhcp_dns dhcp_dns = {0};
static struct dp_conf_dhcp_dns dhcpv6_dns = {0};
#ifdef ENABLE_VIRTSVC
static struct dp_conf_virtual_services virtual_services = {0};
#endif

int dp_conf_is_wcmp_enabled(void)
{
	return wcmp_perc < 100;
}

const char *dp_conf_get_eal_a_pf0(void)
{
	return eal_a_pf0;
}

const char *dp_conf_get_eal_a_pf1(void)
{
	return eal_a_pf1;
}

const union dp_ipv6 *dp_conf_get_underlay_ip(void)
{
	return &underlay_ip;
}

const struct dp_conf_dhcp_dns *dp_conf_get_dhcp_dns(void)
{
	return &dhcp_dns;
}

const struct dp_conf_dhcp_dns *dp_conf_get_dhcpv6_dns(void)
{
	return &dhcpv6_dns;
}

#ifdef ENABLE_VIRTSVC
const struct dp_conf_virtual_services *dp_conf_get_virtual_services(void)
{
	return &virtual_services;
}
#endif

static int add_dhcpv6_dns(const char *str)
{
	union dp_ipv6 ipv6;
	void *tmp;

	if (DP_FAILED(dp_str_to_ipv6(str, &ipv6))) {
		DP_EARLY_ERR("Invalid IPv6 address '%s'", str);
		return DP_ERROR;
	}

	// RFC 2132 - array length is stored in a byte
	if (dhcpv6_dns.len + sizeof(ipv6) > UINT8_MAX) {
		DP_EARLY_ERR("Too many DHCPv6 DNS addresses specified");
		return DP_ERROR;
	}

	tmp = realloc(dhcpv6_dns.array, dhcpv6_dns.len + sizeof(ipv6));
	if (!tmp) {
		DP_EARLY_ERR("Cannot allocate memory for DHCPv6 DNS address");
		return DP_ERROR;
	}
	dhcpv6_dns.array = tmp;

	rte_memcpy(&dhcpv6_dns.array[dhcpv6_dns.len], &ipv6, sizeof(ipv6));
	dhcpv6_dns.len += sizeof(ipv6);
	return DP_OK;
}

static int add_dhcp_dns(const char *str)
{
	void *tmp;
	struct in_addr addr;

	if (inet_aton(str, &addr) != 1) {
		DP_EARLY_ERR("Invalid IPv4 address '%s'", str);
		return DP_ERROR;
	}

	// RFC 2132 - array length is stored in a byte
	if (dhcp_dns.len + sizeof(addr.s_addr) > UINT8_MAX) {
		DP_EARLY_ERR("Too many DHCP DNS addresses specified");
		return DP_ERROR;
	}

	tmp = realloc(dhcp_dns.array, dhcp_dns.len + sizeof(addr.s_addr));
	if (!tmp) {
		DP_EARLY_ERR("Cannot allocate memory for DNS address");
		return DP_ERROR;
	}
	dhcp_dns.array = tmp;

	rte_memcpy(&dhcp_dns.array[dhcp_dns.len], &addr.s_addr, sizeof(addr.s_addr));
	dhcp_dns.len += sizeof(addr.s_addr);
	return DP_OK;
}

#ifdef ENABLE_VIRTSVC
static int add_virtsvc(uint8_t proto, const char *str)
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
	from_port = htons((uint16_t)longport);

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
	to_port = htons((uint16_t)longport);

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

static const struct option *get_opt_by_name(const char *name)
{
	const struct option *longopt;

	// accessing the generated longopts array here
	for (longopt = dp_conf_longopts; longopt->name; ++longopt)
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
		return dp_argparse_string(value, eal_a_pf0, sizeof(eal_a_pf0));

	if (!strcmp(key, "a-pf1"))
		return dp_argparse_string(value, eal_a_pf1, sizeof(eal_a_pf1));

	// Otherwise support all long options
	if (!longopt) {
		DP_EARLY_ERR("Config file: unknown key '%s'", key);
		return DP_ERROR;
	}

	// This is re-using the function generated by dp_conf_generate.py
	// that parses a single option
	return dp_conf_parse_arg(longopt->val, value);
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

void dp_conf_free(void)
{
	free(dhcp_dns.array);
	free(dhcpv6_dns.array);
#ifdef ENABLE_VIRTSVC
	free(virtual_services.entries);
#endif
}

// Implement required functions for dp_conf_parse_args()
static void dp_argparse_version(void)
{
	printf("DP Service version %s\n", DP_SERVICE_VERSION);
}

static int dp_argparse_opt_ipv6(const char *arg)
{
	if (DP_FAILED(dp_str_to_ipv6(arg, &underlay_ip))) {
		DP_EARLY_ERR("Invalid IPv6 address format: '%s'", arg);
		return DP_ERROR;
	}
	return DP_OK;
}

static int dp_argparse_opt_dhcp_dns(const char *arg)
{
	return add_dhcp_dns(arg);
}

static int dp_argparse_opt_dhcpv6_dns(const char *arg)
{
	return add_dhcpv6_dns(arg);
}

#ifdef ENABLE_VIRTSVC
static int dp_argparse_opt_udp_virtsvc(const char *arg)
{
	return add_virtsvc(IPPROTO_UDP, arg);
}

static int dp_argparse_opt_tcp_virtsvc(const char *arg)
{
	return add_virtsvc(IPPROTO_TCP, arg);
}
#endif
