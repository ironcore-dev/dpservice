#include "monitoring/dp_graphtrace.h"

#include <regex.h>
#include <rte_mbuf.h>

#include "dp_conf.h"
#include "dp_error.h"
#include "dp_log.h"
#include "dpdk_layer.h"
#include "monitoring/dp_graphtrace_shared.h"
#include "monitoring/dp_pcap.h"
#include "rte_flow/dp_rte_flow_init.h"
#include "rte_flow/dp_rte_flow.h"
#include "monitoring/dp_event.h"

#ifdef ENABLE_PYTEST
#	include "dp_conf.h"
static enum dp_graphtrace_loglevel graphtrace_loglevel;
#endif

#define DP_IS_NUL_TERMINATED(ARRAY) (strnlen((ARRAY), sizeof(ARRAY)) < sizeof(ARRAY))

int _dp_graphtrace_flags;
bool _dp_graphtrace_enabled = false;
bool _dp_graphtrace_hw_enabled = false;

static struct dp_graphtrace graphtrace;
static bool offload_enabled;
static bool nodename_filtered;
static regex_t nodename_re;
static bool bpf_filtered;
static struct bpf_program bpf;

static int dp_graphtrace_init_memory(void)
{
	// DPDK recommendation for mempool size: power of 2 minus one for best memory utilization
	// So using ringbuffer size minus one, when the ring buffer is (almost) full, allocation will start failing
	// (this is intentional, see below)
	graphtrace.mempool = rte_pktmbuf_pool_create(DP_GRAPHTRACE_MEMPOOL_NAME, DP_GRAPHTRACE_RINGBUF_SIZE-1,
											 DP_MEMPOOL_CACHE_SIZE, DP_MBUF_PRIV_DATA_SIZE + sizeof(struct dp_graphtrace_pktinfo),
											 RTE_MBUF_DEFAULT_BUF_SIZE,
											 rte_socket_id());
	if (!graphtrace.mempool) {
		DPS_LOG_ERR("Cannot allocate graphtrace pool", DP_LOG_RET(rte_errno));
		return DP_ERROR;
	}

	graphtrace.ringbuf = rte_ring_create(DP_GRAPHTRACE_RINGBUF_NAME, DP_GRAPHTRACE_RINGBUF_SIZE,
										 rte_socket_id(), RING_F_SC_DEQ | RING_F_SP_ENQ);
	if (!graphtrace.ringbuf) {
		DPS_LOG_ERR("Cannot create graphtrace ring buffer", DP_LOG_RET(rte_errno));
		rte_mempool_free(graphtrace.mempool);
		return DP_ERROR;
	}

	graphtrace.filters = rte_memzone_reserve(DP_GRAPHTRACE_FILTERS_NAME, sizeof(struct dp_graphtrace_params),
											 rte_socket_id(), 0);
	if (!graphtrace.filters) {
		DPS_LOG_ERR("Cannot create graphtrace filter definition memory", DP_LOG_RET(rte_errno));
		rte_mempool_free(graphtrace.mempool);
		rte_ring_free(graphtrace.ringbuf);
		return DP_ERROR;
	}

	offload_enabled = dp_conf_is_offload_enabled();

	return DP_OK;
}

static void dp_graphtrace_free_memory(void)
{
	rte_ring_free(graphtrace.ringbuf);
	graphtrace.ringbuf = NULL;
	rte_mempool_free(graphtrace.mempool);
	graphtrace.mempool = NULL;
	rte_memzone_free(graphtrace.filters);
	graphtrace.filters = NULL;
}

static int dp_handle_graphtrace_start(const struct dp_graphtrace_mp_request *request)
{
	struct dp_graphtrace_params *filters = (struct dp_graphtrace_params *)graphtrace.filters->addr;
	int ret;

	// there are additional parameters in shared memory (cannot fit into the request)
	if (!DP_IS_NUL_TERMINATED(filters->node_regex)
		|| !DP_IS_NUL_TERMINATED(filters->filter_string))
		return -EINVAL;

	nodename_filtered = *filters->node_regex;
	if (nodename_filtered) {
		if (regcomp(&nodename_re, filters->node_regex, REG_NOSUB) != 0)
			return -EINVAL;
	}

	bpf_filtered = *filters->filter_string;
	if (bpf_filtered) {
		if (DP_FAILED(dp_compile_bpf(&bpf, filters->filter_string))) {
			if (nodename_filtered)
				regfree(&nodename_re);
			return -EINVAL;
		}
	}

	// not making the error code better since 'start.hw' branch will be removed anyway
	if (request->params.start.hw) {
		if (!offload_enabled) {
			if (nodename_filtered)
				regfree(&nodename_re);
			if (bpf_filtered)
				dp_free_bpf(&bpf);
			return -EPERM;
		}

		ret = dp_send_event_hardware_capture_start_msg();
		if (DP_FAILED(ret)) {
			DPS_LOG_ERR("Cannot send hardware capture start message");
			if (nodename_filtered)
				regfree(&nodename_re);
			if (bpf_filtered)
				dp_free_bpf(&bpf);
			return ret;
		}

		_dp_graphtrace_hw_enabled = true;
		DPS_LOG_INFO("Offloaded packet tracing enabled");
	}

	_dp_graphtrace_flags = 0;
	if (request->params.start.drops)
		_dp_graphtrace_flags |= DP_GRAPHTRACE_FLAG_DROPS;
	if (request->params.start.nodes)
		_dp_graphtrace_flags |= DP_GRAPHTRACE_FLAG_NODES;

	_dp_graphtrace_enabled = true;
	DPS_LOG_INFO("Graphtrace enabled");
	return DP_OK;
}

static int dp_handle_graphtrace_stop(void)
{
	if (_dp_graphtrace_enabled) {
		_dp_graphtrace_enabled = false;
		if (nodename_filtered)
			regfree(&nodename_re);
		if (bpf_filtered)
			dp_free_bpf(&bpf);
		DPS_LOG_INFO("Graphtrace disabled");
	}
	if (_dp_graphtrace_hw_enabled) {
		if (DP_FAILED(dp_send_event_hardware_capture_stop_msg())) {
			DPS_LOG_ERR("Cannot send hardware capture stop message");
			return DP_ERROR;
		}
		_dp_graphtrace_hw_enabled = false;
		DPS_LOG_INFO("Offloaded packet tracing disabled");
	}
	return DP_OK;
}

static __rte_always_inline
void dp_handle_graphtrace_request(const struct rte_mp_msg *mp_msg, struct dp_graphtrace_mp_reply *reply)
{
	const struct dp_graphtrace_mp_request *request = (const struct dp_graphtrace_mp_request *)mp_msg->param;
	int ret;

	if (mp_msg->len_param != sizeof(struct dp_graphtrace_mp_request)) {
		DPS_LOG_WARNING("Invalid graphtrace request message size", DP_LOG_VALUE(mp_msg->len_param));
		reply->error_code = -EMSGSIZE;
		return;
	}

	switch (request->action) {
	case DP_GRAPHTRACE_ACTION_START:
		ret = dp_handle_graphtrace_start(request);
		reply->error_code = ret;
		return;
	case DP_GRAPHTRACE_ACTION_STOP:
		ret = dp_handle_graphtrace_stop();
		reply->error_code = ret;
		return;
	default:
		DPS_LOG_WARNING("Unknown graphtrace request action", DP_LOG_VALUE(request->action));
		reply->error_code = -EINVAL;
		return;
	}
}

static int dp_handle_mp_graphtrace_action(const struct rte_mp_msg *mp_msg, const void *peer)
{
	struct rte_mp_msg mp_reply;

	dp_handle_graphtrace_request(mp_msg, (struct dp_graphtrace_mp_reply *)mp_reply.param);

	rte_strscpy(mp_reply.name, DP_MP_ACTION_GRAPHTRACE, sizeof(mp_reply.name));
	mp_reply.len_param = sizeof(struct dp_graphtrace_mp_reply);
	mp_reply.num_fds = 0;
	if (DP_FAILED(rte_mp_reply(&mp_reply, peer))) {
		DPS_LOG_ERR("Cannot reply to graphtrace request", DP_LOG_RET(rte_errno));
		return DP_ERROR;
	}

	return DP_OK;
}

int dp_graphtrace_init(void)
{
	int ret;

	ret = dp_graphtrace_init_memory();
	if (DP_FAILED(ret)) {
		DPS_LOG_ERR("Failed to init memzone for dp graphtrace", DP_LOG_RET(ret));
		return DP_ERROR;
	}

	ret = rte_mp_action_register(DP_MP_ACTION_GRAPHTRACE, dp_handle_mp_graphtrace_action);
	if (DP_FAILED(ret)) {
		DPS_LOG_ERR("Cannot register graphtrace action", DP_LOG_RET(ret));
		dp_graphtrace_free_memory();
		return DP_ERROR;
	}

#ifdef ENABLE_PYTEST
	graphtrace_loglevel = dp_conf_get_graphtrace_loglevel();
#endif
	return DP_OK;
}

void dp_graphtrace_free(void)
{
	rte_mp_action_unregister(DP_MP_ACTION_GRAPHTRACE);
	dp_graphtrace_free_memory();
}


static __rte_always_inline
bool dp_is_node_match(regex_t *re, const struct rte_node *node, const struct rte_node *next_node)
{
	if (node)
		return regexec(re, node->name, 0, NULL, 0) == 0;
	else if (next_node)
		return regexec(re, next_node->name, 0, NULL, 0) == 0;
	else
		return false;
}

void _dp_graphtrace_send(enum dp_graphtrace_pkt_type type,
						 const struct rte_node *node,
						 const struct rte_node *next_node,
						 void **objs, uint16_t nb_objs,
						 uint16_t dst_port_id)
{
	uint16_t nb_dups = 0;
	struct rte_mbuf *dups[nb_objs];
	struct rte_mbuf *dup;
	struct dp_graphtrace_pktinfo *pktinfo;
	uint32_t sent;

	for (uint32_t i = 0; i < nb_objs; ++i) {
		if (nodename_filtered && !dp_is_node_match(&nodename_re, node, next_node))
			continue;
		if (bpf_filtered && !dp_is_bpf_match(&bpf, objs[i]))
			continue;
		dup = rte_pktmbuf_copy(objs[i], graphtrace.mempool, 0, UINT32_MAX);
		if (likely(!dup)) {
			// allocation (pool size) is designed to fail when the ringbuffer is (almost) full
			// this prevent unnecessary copying and immediate freeing after enqueue() fails
			break;
		}
		dups[nb_dups++] = dup;
		pktinfo = dp_get_graphtrace_pktinfo(dup);
		pktinfo->pktid = dp_get_pkt_mark(objs[i])->id;
		pktinfo->pkt_type = type;
		pktinfo->node = node;
		pktinfo->next_node = next_node;
		pktinfo->dst_port_id = dst_port_id;
	}

	if (likely(nb_dups == 0))
		return;

	// NOTE: calls Single-Producer version directly for optimization
	// (needs to reflect the mode given in rte_ring_create())
	sent = rte_ring_sp_enqueue_burst(graphtrace.ringbuf, (void *)dups, nb_dups, NULL);
	if (unlikely(sent < nb_dups)) {
		// Due to the mempool size being smaller than ring size, this should never happen
		DPS_LOG_WARNING("Graphtrace ring is full");
		rte_pktmbuf_free_bulk(&dups[sent], nb_dups - sent);
	}
}

#ifdef ENABLE_PYTEST
__rte_format_printf(2, 3)
static void dp_graphtrace_log(const void *obj, const char *format, ...)
{
	char buf[1024];
	va_list args;
	int pos;

	va_start(args, format);
	pos = vsnprintf(buf, sizeof(buf), format, args);
	va_end(args);

	dp_graphtrace_sprint(obj, buf + pos, sizeof(buf) - pos);

	DP_STRUCTURED_LOG(DEBUG, GRAPH, buf);
}

void _dp_graphtrace_log_node(const struct rte_node *node, void *obj)
{
	if (graphtrace_loglevel >= DP_GRAPHTRACE_LOGLEVEL_RECV)
		dp_graphtrace_log(obj, "%-14s: %3u                  : ",
					   node->name, dp_get_pkt_mark(obj)->id);
}

void _dp_graphtrace_log_node_burst(const struct rte_node *node, void **objs, uint16_t nb_objs)
{
	if (graphtrace_loglevel >= DP_GRAPHTRACE_LOGLEVEL_RECV)
		for (uint32_t i = 0; i < nb_objs; ++i)
			dp_graphtrace_log(objs[i], "%-14s: %3u                  : ",
						   node->name, dp_get_pkt_mark(objs[i])->id);
}

void _dp_graphtrace_log_next(const struct rte_node *node, void *obj, rte_edge_t next_index)
{
	if (graphtrace_loglevel >= DP_GRAPHTRACE_LOGLEVEL_NEXT)
		dp_graphtrace_log(obj, "%-14s: %3u -> %-14s: ",
					   node->name, dp_get_pkt_mark(obj)->id, node->nodes[next_index]->name);
}

void _dp_graphtrace_log_next_burst(const struct rte_node *node, void **objs, uint16_t nb_objs, rte_edge_t next_index)
{
	if (graphtrace_loglevel >= DP_GRAPHTRACE_LOGLEVEL_NEXT)
		for (uint32_t i = 0; i < nb_objs; ++i)
			dp_graphtrace_log(objs[i], "%-11s #%u: %3u -> %-14s: ",
						   node->name, i, dp_get_pkt_mark(objs[i])->id, node->nodes[next_index]->name);
}

void _dp_graphtrace_log_rx_burst(const struct rte_node *node, void **objs, uint16_t nb_objs)
{
	if (graphtrace_loglevel >= DP_GRAPHTRACE_LOGLEVEL_NEXT)
		for (uint32_t i = 0; i < nb_objs; ++i)
			dp_graphtrace_log(objs[i], "PORT %-9u: %3u >> %-11s #%u: ",
						   ((struct rte_mbuf *)objs[i])->port, dp_get_pkt_mark(objs[i])->id, node->name, i);
}

void _dp_graphtrace_log_tx_burst(const struct rte_node *node, void **objs, uint16_t nb_objs, uint16_t port_id)
{
	if (graphtrace_loglevel >= DP_GRAPHTRACE_LOGLEVEL_NEXT)
		for (uint32_t i = 0; i < nb_objs; ++i)
			dp_graphtrace_log(objs[i], "%-11s #%u: %3u >> PORT %-9u: ",
						   node->name, i, dp_get_pkt_mark(objs[i])->id, port_id);
}

void _dp_graphtrace_log_drop_burst(const struct rte_node *node, void **objs, uint16_t nb_objs)
{
	if (graphtrace_loglevel >= DP_GRAPHTRACE_LOGLEVEL_NEXT)
		for (uint32_t i = 0; i < nb_objs; ++i)
			dp_graphtrace_log(objs[i], "%-11s #%u: %3u >> DROP %-9s: ",
						   node->name, i, dp_get_pkt_mark(objs[i])->id, "");
}
#endif  // ENABLE_PYTEST
