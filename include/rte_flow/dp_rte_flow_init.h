#ifndef __INCLUDE_DP_RTE_FLOW_INIT_H
#define __INCLUDE_DP_RTE_FLOW_INIT_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <unistd.h>
#include "rte_malloc.h"
#include "dp_rte_flow.h"

void dp_install_isolated_mode_ipip(int port_id, uint8_t proto_id);
void dp_install_isolated_mode_geneve(int port_id);

#ifdef __cplusplus
}
#endif

#endif /* __INCLUDE_DP_RTE_FLOW_INIT_H */
