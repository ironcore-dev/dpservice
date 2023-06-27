#include "monitoring/dp_graphtrace.h"

#include <rte_mbuf.h>

#include "dp_error.h"
#include "dp_log.h"
#include "dpdk_layer.h"
#include "monitoring/dp_graphtrace_shared.h"

#ifdef ENABLE_PYTEST
#	include "dp_conf.h"
// real id in df_ptr would be better, but that requires initializing df_ptr in rx nodes
#	define DP_GRAPHTRACE_PKT_ID(PKT) (PKT)
static enum dp_graphtrace_loglevel graphtrace_loglevel;
#endif

static struct dp_graphtrace graphtrace;


int dp_graphtrace_init()
{
	// DPDK recommendation for mempool size: power of 2 minus one for best memory utilization
	// So using ringbuffer size minus one, when the ring buffer is (almost) full, allocation will start failing
	// (this is intentional, see below)
	graphtrace.mempool = rte_pktmbuf_pool_create(DP_GRAPHTRACE_MEMPOOL_NAME, DP_GRAPHTRACE_RINGBUF_SIZE-1,
											 MEMPOOL_CACHE_SIZE, DP_MBUF_PRIV_DATA_SIZE + sizeof(struct dp_graphtrace_pktinfo),
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
#ifdef ENABLE_PYTEST
	graphtrace_loglevel = dp_conf_get_graphtrace_loglevel();
#endif
	return DP_OK;
}

void dp_graphtrace_free()
{
	rte_ring_free(graphtrace.ringbuf);
	rte_mempool_free(graphtrace.mempool);
}


void _dp_graphtrace_send(struct rte_node *node, struct rte_node *next_node, void **objs, uint16_t nb_objs)
{
	uint16_t nb_dups = 0;
	struct rte_mbuf *dups[nb_objs];
	struct rte_mbuf *dup;
	struct dp_graphtrace_pktinfo *pktinfo;
	uint sent;

	for (uint i = 0; i < nb_objs; ++i) {
		dup = rte_pktmbuf_copy(objs[i], graphtrace.mempool, 0, UINT32_MAX);
		if (likely(!dup)) {
			// allocation (pool size) is designed to fail when the ringbuffer is (almost) full
			// this prevent unnecessary copying and immediate freeing after enqueue() fails
			break;
		} else {
			dups[nb_dups++] = dup;
			pktinfo = dp_get_graphtrace_pktinfo(dup);
			// currently, simple mbuf address is used as an id
			// as custom ids would require df_ptr access in rx nodes
			pktinfo->pktid = objs[i];
			pktinfo->node = node;
			pktinfo->next_node = next_node;
		}
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
static void dp_graphtrace_log(void *obj, const char *format, ...)
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

void _dp_graphtrace_log_node(struct rte_node *node, void *obj)
{
	if (graphtrace_loglevel >= DP_GRAPHTRACE_LOGLEVEL_RECV)
		dp_graphtrace_log(obj, "%-14s: %p                  : ",
					   node->name, DP_GRAPHTRACE_PKT_ID(obj));
}

void _dp_graphtrace_log_node_burst(struct rte_node *node, void **objs, uint16_t nb_objs)
{
	if (graphtrace_loglevel >= DP_GRAPHTRACE_LOGLEVEL_RECV)
		for (uint i = 0; i < nb_objs; ++i)
			dp_graphtrace_log(objs[i], "%-14s: %p                  : ",
						   node->name, DP_GRAPHTRACE_PKT_ID(objs[i]));
}

void _dp_graphtrace_log_next(struct rte_node *node, void *obj, rte_edge_t next_index)
{
	if (graphtrace_loglevel >= DP_GRAPHTRACE_LOGLEVEL_NEXT)
		dp_graphtrace_log(obj, "%-14s: %p -> %-14s: ",
					   node->name, DP_GRAPHTRACE_PKT_ID(obj), node->nodes[next_index]->name);
}

void _dp_graphtrace_log_next_burst(struct rte_node *node, void **objs, uint16_t nb_objs, rte_edge_t next_index)
{
	if (graphtrace_loglevel >= DP_GRAPHTRACE_LOGLEVEL_NEXT)
		for (uint i = 0; i < nb_objs; ++i)
			dp_graphtrace_log(objs[i], "%-11s #%u: %p -> %-14s: ",
						   node->name, i, DP_GRAPHTRACE_PKT_ID(objs[i]), node->nodes[next_index]->name);
}

void _dp_graphtrace_log_tx_burst(struct rte_node *node, void **objs, uint16_t nb_objs, uint16_t port_id)
{
	if (graphtrace_loglevel >= DP_GRAPHTRACE_LOGLEVEL_NEXT)
		for (uint i = 0; i < nb_objs; ++i)
			dp_graphtrace_log(objs[i], "%-11s #%u: %p >> PORT %-9u: ",
						   node->name, i, DP_GRAPHTRACE_PKT_ID(objs[i]), port_id);
}
#endif  // ENABLE_PYTEST
