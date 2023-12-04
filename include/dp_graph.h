// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#ifndef _INCLUDE_DP_GRAPH_H_
#define _INCLUDE_DP_GRAPH_H_

#include <rte_graph.h>

#define DP_GRAPH_NAME_PREFIX "dp_graph_"

#ifdef __cplusplus
extern "C" {
#endif

int dp_graph_init(void);
void dp_graph_free(void);

struct rte_graph *dp_graph_get(void);

#ifdef __cplusplus
}
#endif

#endif
