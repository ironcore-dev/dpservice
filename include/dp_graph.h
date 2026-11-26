// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#ifndef _INCLUDE_DP_GRAPH_H_
#define _INCLUDE_DP_GRAPH_H_

#include <rte_branch_prediction.h>
#include <rte_graph.h>

#define DP_GRAPH_NAME_PREFIX "dp_graph_"

#ifdef __cplusplus
extern "C" {
#endif

int dp_graph_init(void);
void dp_graph_free(void);

struct rte_graph *dp_graph_get(void);

// hidden variable for inline functions to access
extern bool _dp_graph_sources_dirty;

void dp_graph_rebuild_sources(void);

// port allocation changed, its Rx node needs to be added to/removed from the walk
static __rte_always_inline
void dp_graph_sources_changed(void)
{
	_dp_graph_sources_dirty = true;
}

// only call on the worker lcore between graph walks
static __rte_always_inline
void dp_graph_update_sources(void)
{
	if (unlikely(_dp_graph_sources_dirty))
		dp_graph_rebuild_sources();
}

#ifdef __cplusplus
}
#endif

#endif
