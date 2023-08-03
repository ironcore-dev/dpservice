#ifndef __INCLUDE_DP_CONF_H__
#define __INCLUDE_DP_CONF_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include <rte_byteorder.h>

#ifdef ENABLE_VIRTSVC
struct dp_conf_virtsvc {
	uint8_t    proto;
	rte_be32_t virtual_addr;
	rte_be16_t virtual_port;
	uint8_t    service_addr[16];
	rte_be16_t service_port;
};

struct dp_conf_virtual_services {
	int nb_entries;
	struct dp_conf_virtsvc *entries;
};
#endif

struct dp_conf_dhcp_dns {
	int len;
	uint8_t *array;
};

enum dp_conf_runmode {
	DP_CONF_RUNMODE_NORMAL,	/**< Start dp_service normally */
	DP_CONF_RUNMODE_EXIT,	/**< End succesfully (e.g. for --help etc.) */
	DP_CONF_RUNMODE_ERROR	/**< Error parsing arguments */
};

enum dp_conf_runmode dp_conf_parse_args(int argc, char **argv);

int dp_conf_parse_file(const char *filename);

void dp_conf_free(void);

// Generated getters to access current configuration
#include "dp_conf_opts.h"

// Custom getters
int dp_conf_is_wcmp_enabled(void);
const char *dp_conf_get_eal_a_pf0(void);
const char *dp_conf_get_eal_a_pf1(void);
const struct dp_conf_dhcp_dns *dp_conf_get_dhcp_dns(void);
#ifdef ENABLE_VIRTSVC
const struct dp_conf_virtual_services *dp_conf_get_virtual_services(void);
#endif

#ifdef __cplusplus
}
#endif

#endif
