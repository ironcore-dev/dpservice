#ifndef __DP_GRPC_QUEUE_H__
#define __DP_GRPC_QUEUE_H__

#include <stdint.h>
#include <rte_mbuf.h>
#include "dp_error.h"
#include "dp_grpc_impl.h"

#ifdef __cplusplus
extern "C" {
#endif

int dp_send_to_worker(dp_request *req);

int dp_recv_from_worker(dp_reply *rep, uint16_t request_type);

typedef void (*dp_recv_array_callback)(void *reply, void *context);

int dp_recv_array_from_worker(size_t item_size, dp_recv_array_callback callback, void *context, uint16_t request_type);

#ifdef __cplusplus
}
#endif
#endif
