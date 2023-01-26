#ifndef __INCLUDE_DP_CONF_H__
#define __INCLUDE_DP_CONF_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>

struct dp_conf_dhcp_dns {
	int len;
	const uint8_t *array;
};

enum dp_conf_runmode {
	DP_CONF_RUNMODE_NORMAL,	/**< Start dp_service normally */
	DP_CONF_RUNMODE_EXIT,	/**< End succesfully (e.g. for --help etc.) */
	DP_CONF_RUNMODE_ERROR	/**< Error parsing arguments */
};

enum dp_conf_runmode dp_conf_parse_args(int argc, char **argv);

int dp_conf_parse_file(const char *filename);

void dp_conf_free();

// Generated getters to access current configuration
#include "dp_conf_opts.h"

// Custom getters
int dp_conf_is_wcmp_enabled();
const char *dp_conf_get_eal_a_pf0();
const char *dp_conf_get_eal_a_pf1();
const struct dp_conf_dhcp_dns *dp_conf_get_dhcp_dns();


#ifdef __cplusplus
}
#endif

#endif
