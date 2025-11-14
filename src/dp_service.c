// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include "dp_conf.h"
#include "dp_error.h"
#include "dp_flow.h"
#include "dp_graph.h"
#include "dp_lb.h"
#include "dp_log.h"
#include "dp_iface.h"
#include "dp_multi_path.h"
#include "dp_nat.h"
#include "dp_port.h"
#include "dp_telemetry.h"
#include "dp_internal_stats.h"
#include "dp_version.h"
#include "dp_vnf.h"
#include "dp_vni.h"
#ifdef ENABLE_VIRTSVC
#	include "dp_virtsvc.h"
#endif
#include "dpdk_layer.h"
#include "grpc/dp_grpc_thread.h"
#include "rte_flow/dp_rte_async_flow.h"

static char **dp_argv;
static int dp_argc;
static char *dp_mlx_args[4];

static void dp_args_free_mellanox(void)
{
	for (int i = 0; i < 4; ++i)
		free(dp_mlx_args[i]);
	free(dp_argv);
}

static int dp_args_add_mellanox(int *orig_argc, char ***orig_argv)
{
	int curarg;
	int argend = -1;
	int argc = *orig_argc;
	char **argv = *orig_argv;

	// will be adding two devices (4 args) + terminator
	dp_argv = (char **)calloc(argc + 5, sizeof(*dp_argv));
	if (!dp_argv) {
		DP_EARLY_ERR("Cannot allocate argument array");
		return DP_ERROR;
	}

	// copy EAL args
	for (curarg = 0; curarg < argc; curarg++) {
		if (strcmp(argv[curarg], "--") == 0) {
			argend = curarg;
			break;
		} else {
			dp_argv[curarg] = argv[curarg];
		}
	}
	// add mellanox args (remember that they can be written to, so strdup())
	dp_mlx_args[0] = dp_argv[curarg++] = strdup("-a");
	dp_mlx_args[1] = dp_argv[curarg++] = strdup(dp_conf_get_eal_a_pf0());
	if (dp_conf_get_eal_a_pf1()[0] == '\0') {
		dp_mlx_args[2] = dp_argv[curarg++] = strdup("");
		dp_mlx_args[3] = dp_argv[curarg++] = strdup("");
	} else {
		dp_mlx_args[2] = dp_argv[curarg++] = strdup("-a");
		dp_mlx_args[3] = dp_argv[curarg++] = strdup(dp_conf_get_eal_a_pf1());
	}
	if (!dp_mlx_args[0] || !dp_mlx_args[1] || !dp_mlx_args[2] || !dp_mlx_args[3]) {
		DP_EARLY_ERR("Cannot allocate Mellanox arguments");
		dp_args_free_mellanox();
		return DP_ERROR;
	}

	// add original dpservice args
	if (argend >= 0) {
		for (int j = argend; j < argc; ++j)
			dp_argv[curarg++] = argv[j];
	}
	dp_argv[curarg] = NULL;
	dp_argc = curarg;

	*orig_argc = dp_argc;
	*orig_argv = dp_argv;
	return DP_OK;
}

static bool dp_is_mellanox_opt_set(void)
{
	return dp_conf_get_eal_a_pf0()[0] != '\0'
		|| dp_conf_get_eal_a_pf1()[0] != '\0';
}

static int dp_eal_init(int *argc_ptr, char ***argv_ptr)
{
	if (dp_is_mellanox_opt_set())
		if (DP_FAILED(dp_args_add_mellanox(argc_ptr, argv_ptr)))
			return DP_ERROR;
	return rte_eal_init(*argc_ptr, *argv_ptr);
}

static void dp_eal_cleanup(void)
{
	rte_eal_cleanup();
	if (dp_is_mellanox_opt_set())
		dp_args_free_mellanox();
}

static void signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
		// this is specifically printf() to communicate with the sender
		printf("\n\nSignal %d received, preparing to exit...\n", signum);
		dp_force_quit();
	}
}

static int setup_sighandlers(void)
{
	struct sigaction old_action;
	struct sigaction sig_action = {
		.sa_handler = signal_handler,
		.sa_flags = SA_RESETHAND,  // second Ctrl+C will terminate forcefully
	};

	// man(2): 'sigaction() returns 0 on success <...> errno is set to indicate the error.'
	if (sigaction(SIGINT, &sig_action, &old_action)
		|| sigaction(SIGTERM, &sig_action, &old_action)
	) {
		DPS_LOG_ERR("Cannot setup signal handling", DP_LOG_RET(errno));
		return DP_ERROR;
	}
	return DP_OK;
}

static int init_interfaces(void)
{
	int pf0_socket_id;

	dp_multipath_init();

	if (DP_FAILED(dp_ports_init()))
		return DP_ERROR;

	// only now (after init) this is valid
	pf0_socket_id = dp_get_pf0()->socket_id;

#ifdef ENABLE_VIRTSVC
	if (DP_FAILED(dp_virtsvc_init(pf0_socket_id)))
		return DP_ERROR;
#endif
	if (DP_FAILED(dp_graph_init())
		|| DP_FAILED(dp_telemetry_init()))
		return DP_ERROR;

	if (DP_FAILED(dp_start_pf_port(0)))
		return DP_ERROR;

	if (DP_FAILED(dp_start_pf_port(1)))
		return DP_ERROR;

	if (dp_conf_is_sync_enabled())
		if (DP_FAILED(dp_start_sync_port()))
			return DP_ERROR;

	// VFs are started by GRPC later

	if (DP_FAILED(dp_flow_init(pf0_socket_id))
		|| DP_FAILED(dp_ifaces_init(pf0_socket_id))
		|| DP_FAILED(dp_nat_init(pf0_socket_id))
		|| DP_FAILED(dp_lb_init(pf0_socket_id))
		|| DP_FAILED(dp_vni_init(pf0_socket_id))
		|| DP_FAILED(dp_vnf_init(pf0_socket_id)))
		return DP_ERROR;

	return DP_OK;
}

static void free_interfaces(void)
{
	dp_vnf_free();
	dp_vni_free();
	dp_lb_free();
	dp_nat_free();
	dp_ifaces_free();
	dp_flow_free();
	dp_ports_stop();
	dp_telemetry_free();
	dp_graph_free();
#ifdef ENABLE_VIRTSVC
	dp_virtsvc_free();
#endif
	dp_ports_free();
	// dp_multipath has no free
}

static inline int run_dpdk_service(void)
{
	int result = DP_ERROR;

	if (DP_FAILED(init_interfaces())
		|| DP_FAILED(dp_grpc_thread_start()))
		goto end;

	result = dp_dpdk_main_loop();

	// Proper shutdown of gRPC server does not work
	// thus calling cancel() instead of join() here
	if (DP_FAILED(dp_grpc_thread_cancel()))
		result = DP_ERROR;

end:
	free_interfaces();
	return result;
}

static int run_service(void)
{
	int result;

	// the lower 32 bits are the ones that are actually changing all the time, cast is fine
	srand((unsigned int)rte_rdtsc());

	// pre-init sanity checks
	if (!dp_conf_is_conntrack_enabled() && dp_conf_is_offload_enabled()) {
		DP_EARLY_ERR("Disabled conntrack requires disabled offloading");
		return DP_ERROR;
	}

	if (dp_conf_is_multiport_eswitch()) {
		if (dp_conf_is_offload_enabled()) {
			DP_EARLY_ERR("HW offloading is currently not supported for multi-port eswitch mode");
			return DP_ERROR;
		}
	}

	if (DP_FAILED(dp_log_init()))
		return DP_ERROR;

	dp_log_set_thread_name("control");
	DPS_LOG_INFO("Starting DP Service version " DP_SERVICE_VERSION);
	// from this point on, only DPS_LOG should be used

	if (DP_FAILED(setup_sighandlers())
		|| DP_FAILED(dp_dpdk_layer_init()))
		return DP_ERROR;

	result = run_dpdk_service();

	dp_dpdk_layer_free();

	return result;
}

int main(int argc, char **argv)
{
	int retval = EXIT_SUCCESS;
	int eal_argcount;

	// Read the config file first because it can contain EAL arguments
	// (those need to be injected *before* rte_eal_init())
	if (DP_FAILED(dp_conf_parse_file(getenv("DP_CONF"))))
		return EXIT_FAILURE;

	eal_argcount = dp_eal_init(&argc, &argv);
	if (DP_FAILED(eal_argcount)) {
		DP_EARLY_ERR("Failed to initialize EAL");
		dp_conf_free();
		return EXIT_FAILURE;
	}

	switch (dp_conf_parse_args(argc - eal_argcount, argv + eal_argcount)) {
	case DP_CONF_RUNMODE_ERROR:
		retval = EXIT_FAILURE;
		break;
	case DP_CONF_RUNMODE_EXIT:
		retval = EXIT_SUCCESS;
		break;
	case DP_CONF_RUNMODE_NORMAL:
		retval = DP_FAILED(run_service()) ? EXIT_FAILURE : EXIT_SUCCESS;
		break;
	}

	dp_eal_cleanup();
	dp_conf_free();

	return retval;
}
