// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#ifndef __INCLUDE_DP_CONF_H__
#define __INCLUDE_DP_CONF_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include <rte_byteorder.h>
#include "dp_ipaddr.h"

#ifdef ENABLE_VIRTSVC
struct dp_conf_virtsvc {
	uint8_t			proto;
	rte_be32_t		virtual_addr;
	rte_be16_t		virtual_port;
	union dp_ipv6	service_addr;
	rte_be16_t		service_port;
};

struct dp_conf_virtual_services {
	int						nb_entries;
	struct dp_conf_virtsvc	*entries;
};
#endif

struct dp_conf_dhcp_dns {
	uint8_t	len;
	uint8_t	*array;
};

int dp_conf_parse_file(const char *filename);

void dp_conf_free(void);

// Generated getters to access current configuration
#include "dp_conf_opts.h"

// Custom getters
int dp_conf_is_wcmp_enabled(void);
const char *dp_conf_get_eal_a_pf0(void);
const char *dp_conf_get_eal_a_pf1(void);
const union dp_ipv6 *dp_conf_get_underlay_ip(void);
const struct dp_conf_dhcp_dns *dp_conf_get_dhcp_dns(void);
const struct dp_conf_dhcp_dns *dp_conf_get_dhcpv6_dns(void);

#ifdef ENABLE_PF1_PROXY
const char* dp_get_eal_pf1_proxy_mac_addr(void);
const char* dp_get_eal_pf1_proxy_dev_name(void);
const char* dp_generate_eal_pf1_proxy_params(void);
#endif

#ifdef ENABLE_VIRTSVC
const struct dp_conf_virtual_services *dp_conf_get_virtual_services(void);
#endif

#ifdef __cplusplus
}
#endif

#endif
