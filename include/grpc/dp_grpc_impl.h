// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#ifndef __INCLUDE_DP_GRPC_IMPL_H__
#define __INCLUDE_DP_GRPC_IMPL_H__

#include <rte_mbuf.h>

#ifdef __cplusplus
extern "C" {
#endif

void dp_process_request(struct rte_mbuf *m);

#ifdef __cplusplus
}
#endif
#endif
