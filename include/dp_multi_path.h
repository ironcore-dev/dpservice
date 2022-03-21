#ifndef __INCLUDE_DP_MULTI_PATH_H
#define __INCLUDE_DP_MULTI_PATH_H

#ifdef __cplusplus
extern "C" {
#endif

#include "dp_port.h"

#define port_select_table_size 10

typedef enum{
	OWNER_PORT,
	PEER_PORT,
} egress_pf_port;

void fill_port_select_table(double frac);
egress_pf_port calculate_port_by_hash(uint32_t hash);


#ifdef __cplusplus
}
#endif


#endif /* __INCLUDE_DP_MULTI_PATH_H */
