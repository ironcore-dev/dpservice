#ifndef __INCLUDE_DP_MONITORING_H
#define __INCLUDE_DP_MONITORING_H

#include <stdint.h>
#include <rte_mbuf.h>
#include <net/if.h>
#include "dp_util.h"

#include "dp_link_status.h"

#ifdef __cplusplus
extern "C" {
#endif


typedef enum {
	DP_STATUS_TYPE_UNKNOWN,
	DP_STATUS_TYPE_LINK,
} dp_status_type;

typedef enum {
	DP_STATUS_SCOPE_LOCAL,
	DP_STATUS_SCOPE_REMOTE,
} dp_status_scope;

typedef struct {
	dp_status_type type;
	dp_status_scope scope; 
} dp_status_msg_head;

typedef struct {
	uint16_t port_id;
	uint8_t status;
} dp_link_status;

typedef struct {
	dp_status_msg_head msg_head;
	
	union {
		dp_link_status link_status;
	} status_entry;

} dp_status_msg;

void dp_process_status_msg(struct rte_mbuf *m);

#ifdef __cplusplus
}
#endif
#endif /* __INCLUDE_DP_MONITORING_H */
