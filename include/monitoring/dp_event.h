#ifndef __INCLUDE_DP_EVENT_H__
#define __INCLUDE_DP_EVENT_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <rte_mbuf.h>
#include <rte_ethdev.h>

int dp_link_status_change_event_callback(uint16_t port_id, 
										 enum rte_eth_event_type type,
										 void *param,
										 void *ret_param);
void dp_process_event_link_msg(struct rte_mbuf *m);

int dp_send_event_flow_aging_msg(void);

void dp_process_event_flow_aging_msg(struct rte_mbuf *m);

#ifdef __cplusplus
}
#endif
#endif /* __INCLUDE_DP_EVENT_H__ */
