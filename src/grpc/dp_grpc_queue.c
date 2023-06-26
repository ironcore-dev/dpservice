#include "grpc/dp_grpc_queue.h"
#include "dp_log.h"

int dp_send_to_worker(struct dpgrpc_request *req)
{
	struct rte_mbuf *m;
	int ret;

	m = rte_pktmbuf_alloc(get_dpdk_layer()->rte_mempool);
	if (!m) {
		DPGRPC_LOG_WARNING("Cannot allocate worker request", DP_LOG_GRPCREQUEST(req->type));
		return DP_ERROR;
	}

	assert(m->buf_len - m->data_off >= sizeof(struct dpgrpc_request));
	*rte_pktmbuf_mtod(m, struct dpgrpc_request *) = *req;

	ret = rte_ring_sp_enqueue(get_dpdk_layer()->grpc_tx_queue, m);
	if (DP_FAILED(ret))
		DPGRPC_LOG_WARNING("Cannot enqueue worker request", DP_LOG_RET(ret), DP_LOG_GRPCREQUEST(req->type));

	return ret;
}

int dp_recv_from_worker(struct dpgrpc_reply *reply, uint16_t request_type)
{
	struct rte_mbuf *m;
	int ret;

	ret = rte_ring_sc_dequeue(get_dpdk_layer()->grpc_rx_queue, (void **)&m);
	if (DP_FAILED(ret)) {
		if (ret != -ENOENT)
			DPGRPC_LOG_WARNING("Cannot dequeue worker response", DP_LOG_RET(ret));
		return ret;
	}

	assert(m->buf_len - m->data_off >= sizeof(struct dpgrpc_reply));
	*reply = *rte_pktmbuf_mtod(m, struct dpgrpc_reply *);

	if (reply->type != request_type) {
		DPGRPC_LOG_WARNING("Invalid response received", DP_LOG_GRPCREQUEST(request_type));
		ret = DP_ERROR;
	} else if (reply->is_chained || reply->msg_count != 1) {
		DPGRPC_LOG_WARNING("Single response expected, multiresponse received", DP_LOG_GRPCREQUEST(request_type));
		ret = DP_ERROR;
	}

	rte_pktmbuf_free(m);
	return ret;
}

int dp_recv_array_from_worker(size_t item_size, dp_recv_array_callback callback, void *context, uint16_t request_type)
{
	struct rte_mbuf *m;
	struct dpgrpc_reply *reply;
	uint8_t is_chained;
	int ret;

	do {
		ret = rte_ring_sc_dequeue(get_dpdk_layer()->grpc_rx_queue, (void **)&m);
		if (DP_FAILED(ret)) {
			if (ret != -ENOENT)
				DPGRPC_LOG_WARNING("Cannot dequeue worker response", DP_LOG_RET(ret));
			return ret;
		}
		reply = rte_pktmbuf_mtod(m, struct dpgrpc_reply *);
		if (reply->type != request_type) {
			DPGRPC_LOG_WARNING("Invalid response received", DP_LOG_GRPCREQUEST(request_type));
			return DP_ERROR;
		}
		for (int i = 0; i < reply->msg_count; ++i)
			callback(reply->messages + i * item_size, context);
		is_chained = reply->is_chained;
		rte_pktmbuf_free(m);
	} while (is_chained);

	return DP_OK;
}
