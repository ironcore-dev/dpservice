// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#include "grpc/dp_grpc_responder.h"
#include "dp_log.h"

enum dpgrpc_request_type dp_grpc_init_responder(struct dp_grpc_responder *responder, struct rte_mbuf *req_mbuf)
{
	void *req_payload = rte_pktmbuf_mtod(req_mbuf, void *);

	// request mbuf will be reused to prevent unnecessarry free(request)+alloc(response)
	// so create a copy of the request first
	rte_memcpy(&responder->request, (struct dpgrpc_request *)req_payload, sizeof(responder->request));
	responder->replies[0] = req_mbuf;
	responder->repcount = 1;

	responder->mempool = get_dpdk_layer()->rte_mempool;
	responder->rep_max_size = req_mbuf->buf_len - req_mbuf->data_off - offsetof(struct dpgrpc_reply, messages);
	// by default, only one reply with one message
	responder->rep_capacity = 1;
	responder->msg_size = sizeof(struct dpgrpc_reply);
	responder->rep_msgcount = 0;
	responder->rep = (struct dpgrpc_reply *)req_payload;  // again, due to reusal of the request mbuf
	responder->rep->type = responder->request.type;
	responder->rep->is_chained = 0;
	// msg_count is set at the end (or when rep is full)
	// err_code is set at the end for the first rep

	return responder->request.type;
}

int dp_grpc_alloc_reply(struct dp_grpc_responder *responder)
{
	struct rte_mbuf *m_new;
	struct dpgrpc_reply *rep_new;

	if (responder->rep_capacity > UINT16_MAX) {
		DPGRPC_LOG_WARNING("gRPC response array is too big, truncated", DP_LOG_GRPCREQUEST(responder->request.type));
		return DP_ERROR;
	}

	if (responder->repcount >= RTE_DIM(responder->replies)) {
		DPGRPC_LOG_WARNING("gRPC response array is full, truncated", DP_LOG_GRPCREQUEST(responder->request.type));
		return DP_ERROR;
	}
	m_new = rte_pktmbuf_alloc(responder->mempool);
	if (!m_new) {
		DPGRPC_LOG_WARNING("gRPC response mbuf allocation failed", DP_LOG_GRPCREQUEST(responder->request.type));
		return DP_ERROR;
	}
	// more reply packets follow this one; as gRPC has only one thread, this is safe to do
	responder->rep->is_chained = 1;
	responder->rep->msg_count = (uint16_t)responder->rep_capacity;
	rep_new = rte_pktmbuf_mtod(m_new, struct dpgrpc_reply *);
	rep_new->type = responder->request.type;
	rep_new->is_chained = 0;
	rep_new->err_code = 0;  // only the first reply should hold the error code
	responder->replies[responder->repcount++] = m_new;
	responder->rep_msgcount = 0;
	responder->rep = rte_pktmbuf_mtod(m_new, struct dpgrpc_reply *);
	return DP_OK;
}

void dp_grpc_send_response(struct dp_grpc_responder *responder, int grpc_ret)
{
	unsigned int sent;

	// writing the error code to the first one should be enough (client should check errors first)
	// (responder->repcount starts from 1 (reused request), no possibilily of not having at least one reply)
	rte_pktmbuf_mtod(responder->replies[0], struct dpgrpc_reply *)->err_code = grpc_ret;

	// the last reply is not full
	responder->rep->msg_count = responder->rep_msgcount;

	sent = rte_ring_sp_enqueue_burst(get_dpdk_layer()->grpc_rx_queue, (void * const *)responder->replies, responder->repcount, NULL);
	if (sent != responder->repcount) {
		DPGRPC_LOG_WARNING("Not all gRPC responses were queued", DP_LOG_GRPCREQUEST(responder->request.type),
						   DP_LOG_VALUE(sent), DP_LOG_MAX(responder->repcount));
		rte_pktmbuf_free_bulk(responder->replies + sent, responder->repcount - sent);
	}
}
