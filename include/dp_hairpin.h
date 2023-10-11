#ifndef _DP_HAIRPIN_H_
#define _DP_HAIRPIN_H_

#include "dp_port.h"

#ifdef __cplusplus
extern "C" {
#endif

int dp_hairpin_setup(const struct dp_port *port);
int dp_hairpin_bind(const struct dp_port *port);

#ifdef __cplusplus
}
#endif
#endif
