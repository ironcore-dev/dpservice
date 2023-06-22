#ifndef __DP_GRPC_RESPONDER_H__
#define __DP_GRPC_RESPONDER_H__

#include <stdint.h>
#include <rte_mbuf.h>
#include "dp_error.h"
// TODO(plague): move dp_request and dp_reply definitions here instead
#include "dp_grpc_impl.h"

#ifdef __cplusplus
extern "C" {
#endif

struct dp_grpc_responder {
	dp_request req;
	// reply consists of an array of 'packets'
	struct rte_mbuf *replies[DP_GRPC_REPLY_ARR_SIZE];
	int repcount;
	struct rte_mempool *mempool;
	// each of which can be divided into 'messages' (the actual replies)
	dp_reply *rep;
	size_t rep_max_size;
	size_t msg_size;
	int rep_capacity;
	int rep_msgcount;
};

// returns request's type
uint16_t dp_grpc_init_responder(struct dp_grpc_responder *responder, struct rte_mbuf *req_mbuf);

static inline void *dp_grpc_single_reply(struct dp_grpc_responder *responder)
{
	return responder->rep->messages;  // this is used in place of the parent union (which is anonymous)
}

static inline void dp_grpc_set_multireply(struct dp_grpc_responder *responder, size_t msg_size)
{
	responder->msg_size = msg_size;
	responder->rep_capacity = responder->rep_max_size / msg_size;
	responder->rep_msgcount = 0;
}

int dp_grpc_alloc_reply(struct dp_grpc_responder *responder);

static inline void *dp_grpc_add_reply(struct dp_grpc_responder *responder)
{
	if (responder->rep_msgcount >= responder->rep_capacity)
		if (DP_FAILED(dp_grpc_alloc_reply(responder)))
			return NULL;
	return responder->rep->messages + responder->msg_size * responder->rep_msgcount++;
}

void dp_grpc_send_response(struct dp_grpc_responder *responder, int grpc_ret);

#ifdef __cplusplus
}
#endif
#endif
