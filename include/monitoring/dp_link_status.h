#ifndef __INCLUDE_DP_LINK_STATUS_H
#define __INCLUDE_DP_LINK_STATUS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <rte_mbuf.h>
#include "dp_util.h"
#include "dpdk_layer.h"
#include "dp_monitoring.h"


void dp_port_set_link_status(struct dp_dpdk_layer *dp_layer,int port_id, uint8_t status);

uint8_t dp_port_get_link_status(struct dp_dpdk_layer *dp_layer,int port_id);

int dp_link_status_change_event_callback(uint16_t port_id, 
												enum rte_eth_event_type type, 
												void *param,
												void *ret_param);

int send_link_status_msg(uint16_t port_id, uint8_t status);
void dp_process_link_status_msg(struct rte_mbuf *m);


#ifdef __cplusplus
}
#endif
#endif /* __INCLUDE_DP_LINK_STATUS_H */
