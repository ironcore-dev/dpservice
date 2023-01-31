#include "grpc/dp_grpc_thread.h"
#include <rte_thread.h>
#include "dp_conf.h"
#include "dp_error.h"
#include "dp_log.h"
#include "grpc/dp_grpc_service.h"

static pthread_t grpc_thread_id;

static void *dp_grpc_main_loop(__rte_unused void *arg)
{
	GRPCService *grpc_svc;
	char addr[12];  // '[::]:65535\0'

	dp_log_set_thread_name("grpc");

	grpc_svc = new GRPCService();

	snprintf(addr, sizeof(addr), "[::]:%d", dp_conf_get_grpc_port());

	// we are in a thread, proper teardown would be complicated here, so exit instead
	if (!grpc_svc->run(addr))
		rte_exit(EXIT_FAILURE, "Cannot run without working GRPC server\n");

	delete grpc_svc;
	return NULL;
}

int dp_grpc_thread_start()
{
	int ret = rte_ctrl_thread_create(&grpc_thread_id, "grpc-thread", NULL, dp_grpc_main_loop, NULL);

	if (DP_FAILED(ret))
		DPS_LOG_ERR("Cannot create grpc thread %s", dp_strerror(ret));
	return ret;
}

int dp_grpc_thread_join()
{
	int ret = pthread_join(grpc_thread_id, NULL);  // returns errno on failure

	if (ret) {
		DPS_LOG_ERR("Cannot join grpc thread %s", dp_strerror(ret));
		return DP_ERROR;
	}
	return DP_OK;
}

int dp_grpc_thread_cancel()
{
	int ret = pthread_cancel(grpc_thread_id);  // returns errno on failure

	if (ret) {
		DPS_LOG_ERR("Cannot cancel grpc thread %s", dp_strerror(ret));
		return DP_ERROR;
	}
	return DP_OK;
}
