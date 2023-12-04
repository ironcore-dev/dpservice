// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#ifndef __INCLUDE_GRPC_THREAD_H__
#define __INCLUDE_GRPC_THREAD_H__

#ifdef __cplusplus
extern "C" {
#endif

int dp_grpc_thread_start(void);
int dp_grpc_thread_cancel(void);

#ifdef __cplusplus
}
#endif
#endif
