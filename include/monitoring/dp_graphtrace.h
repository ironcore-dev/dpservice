// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#ifndef __INCLUDE_DP_GRAPHTRACE_H__
#define __INCLUDE_DP_GRAPHTRACE_H__

#include <rte_graph.h>

#include "dp_graphtrace_shared.h"

#ifdef __cplusplus
extern "C" {
#endif

enum dp_graphtrace_loglevel {
	DP_GRAPHTRACE_LOGLEVEL_SILENT,
	DP_GRAPHTRACE_LOGLEVEL_NEXT,
	DP_GRAPHTRACE_LOGLEVEL_RECV,
	DP_GRAPHTRACE_LOGLEVEL_MAX = DP_GRAPHTRACE_LOGLEVEL_RECV
};

int dp_graphtrace_init(void);
void dp_graphtrace_free(void);

void _dp_graphtrace_send(const struct rte_node *node,
						 const struct rte_node *next_node,
						 void **objs, uint16_t nb_objs,
						 uint16_t dst_port_id);

// Logging the trace for debugging
#ifdef ENABLE_PYTEST
	void _dp_graphtrace_log_node(const struct rte_node *node, void *obj);
	void _dp_graphtrace_log_node_burst(const struct rte_node *node, void **objs, uint16_t nb_objs);
	void _dp_graphtrace_log_next(const struct rte_node *node, void *obj, rte_edge_t next_index);
	void _dp_graphtrace_log_next_burst(const struct rte_node *node, void **objs, uint16_t nb_objs, rte_edge_t next_index);
	void _dp_graphtrace_log_rx_burst(const struct rte_node *node, void **objs, uint16_t nb_objs);
	void _dp_graphtrace_log_tx_burst(const struct rte_node *node, void **objs, uint16_t nb_objs, uint16_t port_id);
	void _dp_graphtrace_log_drop_burst(const struct rte_node *node, void **objs, uint16_t nb_objs);
#else
#	define _dp_graphtrace_log_node(NODE, OBJ) (void)0
#	define _dp_graphtrace_log_node_burst(NODE, OBJS, NUM) (void)0
#	define _dp_graphtrace_log_next(NODE, OBJ, NEXT) (void)0
#	define _dp_graphtrace_log_next_burst(NODE, OBJS, NUM, NEXT) (void)0
#	define _dp_graphtrace_log_rx_burst(NODE, OBJS, NUM) (void)0
#	define _dp_graphtrace_log_tx_burst(NODE, OBJS, NUM, PORTID) (void)0
#	define _dp_graphtrace_log_drop_burst(NODE, OBJS, NUM) (void)0
#endif

// Currently "node entered" events are only being logged, not sent out
#define dp_graphtrace_node(NODE, OBJ) _dp_graphtrace_log_node(NODE, OBJ)
#define dp_graphtrace_node_burst(NODE, OBJS, NUM) _dp_graphtrace_log_node_burst(NODE, OBJS, NUM)

#define DP_GRAPHTRACE_FLAG_DROPS 1
#define DP_GRAPHTRACE_FLAG_NODES 2

extern int _dp_graphtrace_flags;
extern bool _dp_graphtrace_enabled;

static __rte_always_inline void dp_graphtrace_next(const struct rte_node *node, void *obj, rte_edge_t next_index)
{
	if (_dp_graphtrace_enabled && (_dp_graphtrace_flags & DP_GRAPHTRACE_FLAG_NODES))
		_dp_graphtrace_send(node, node->nodes[next_index], &obj, 1, -1);
	_dp_graphtrace_log_next(node, obj, next_index);
}

static __rte_always_inline void dp_graphtrace_next_burst(const struct rte_node *node, void **objs, uint16_t nb_objs, rte_edge_t next_index)
{
	if (_dp_graphtrace_enabled && (_dp_graphtrace_flags & DP_GRAPHTRACE_FLAG_NODES))
		_dp_graphtrace_send(node, node->nodes[next_index], objs, nb_objs, -1);
	_dp_graphtrace_log_next_burst(node, objs, nb_objs, next_index);
}

static __rte_always_inline void dp_graphtrace_rx_burst(const struct rte_node *node, void **objs, uint16_t nb_objs)
{
	if (_dp_graphtrace_enabled)
		_dp_graphtrace_send(NULL, node, objs, nb_objs, -1);
	_dp_graphtrace_log_rx_burst(node, objs, nb_objs);
}

static __rte_always_inline void dp_graphtrace_tx_burst(const struct rte_node *node, void **objs, uint16_t nb_objs, uint16_t port_id)
{
	if (_dp_graphtrace_enabled)
		_dp_graphtrace_send(node, NULL, objs, nb_objs, port_id);
	_dp_graphtrace_log_tx_burst(node, objs, nb_objs, port_id);
}

static __rte_always_inline void dp_graphtrace_drop_burst(const struct rte_node *node, void **objs, uint16_t nb_objs)
{
	if (_dp_graphtrace_enabled && (_dp_graphtrace_flags & DP_GRAPHTRACE_FLAG_DROPS))
		_dp_graphtrace_send(node, NULL, objs, nb_objs, -1);
	_dp_graphtrace_log_drop_burst(node, objs, nb_objs);
}


#ifdef __cplusplus
}
#endif

#endif
