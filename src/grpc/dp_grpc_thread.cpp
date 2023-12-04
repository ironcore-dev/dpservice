// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#include "grpc/dp_grpc_thread.h"
#include <rte_lcore.h>
#include <rte_thread.h>
#include "dp_conf.h"
#include "dp_error.h"
#include "dp_log.h"
#include "grpc/dp_grpc_service.h"

static pthread_t grpc_thread_id;
// pthread_t is opaque, must use another value for checking
static bool grpc_thread_started = false;

static void *dp_grpc_main_loop(__rte_unused void *arg)
{
	GRPCService *grpc_svc;
	char addr[12];  // '[::]:65535\0'

	dp_log_set_thread_name("grpc");

	grpc_svc = GRPCService::GetInstance();

	snprintf(addr, sizeof(addr), "[::]:%d", dp_conf_get_grpc_port());

	// we are in a thread, proper teardown would be complicated here, so exit instead
	if (!grpc_svc->run(addr))
		rte_exit(EXIT_FAILURE, "Cannot run without working gRPC server\n");

	GRPCService::Cleanup();
	return NULL;
}

int dp_grpc_thread_start(void)
{
	int ret;

	if (grpc_thread_started) {
		DPS_LOG_WARNING("gRPC thread already started");
		return DP_ERROR;
	}

	ret = rte_ctrl_thread_create(&grpc_thread_id, "grpc-thread", NULL, dp_grpc_main_loop, NULL);
	if (DP_FAILED(ret)) {
		DPS_LOG_ERR("Cannot create gRPC thread", DP_LOG_RET(ret));
		return ret;
	}

	grpc_thread_started = true;
	return DP_OK;
}

int dp_grpc_thread_cancel(void)
{
	int ret;

	// no warning here, this is used for force-quitting
	if (!grpc_thread_started)
		return DP_OK;

	ret = pthread_cancel(grpc_thread_id);  // returns errno on failure
	if (ret) {
		DPS_LOG_ERR("Cannot cancel gRPC thread", DP_LOG_RET(ret));
		return ret;
	}

	grpc_thread_started = false;
	return DP_OK;
}
