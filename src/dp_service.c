#include <errno.h>
#include <signal.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/queue.h>

#include "dp_alias.h"
#include "dp_conf.h"
#include "dp_error.h"
#include "dp_flow.h"
#include "dp_lb.h"
#include "dp_log.h"
#include "dp_lpm.h"
#include "dp_multi_path.h"
#include "dp_nat.h"
#include "dp_port.h"
#include "dp_version.h"
#ifdef ENABLE_VIRTSVC
#	include "dp_virtsvc.h"
#endif
#include "dpdk_layer.h"
#include "grpc/dp_grpc_thread.h"

static char **dp_argv;
static int dp_argc;
static char *dp_mlx_args[4];

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
	dp_mlx_args[2] = dp_argv[curarg++] = strdup("-a");
	dp_mlx_args[3] = dp_argv[curarg++] = strdup(dp_conf_get_eal_a_pf1());
	if (!dp_mlx_args[0] || !dp_mlx_args[1] || !dp_mlx_args[2] || !dp_mlx_args[3]) {
		DP_EARLY_ERR("Cannot allocate Mellanox arguments");
		return DP_ERROR;
	}

	// add original dp_service args
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

static void dp_args_free_mellanox()
{
	for (int i = 0; i < 4; ++i)
		free(dp_mlx_args[i]);
	free(dp_argv);
}

static int dp_eal_init(int *argc_ptr, char ***argv_ptr)
{
	if (dp_is_mellanox_opt_set())
		if (DP_FAILED(dp_args_add_mellanox(argc_ptr, argv_ptr)))
			return DP_ERROR;
	return rte_eal_init(*argc_ptr, *argv_ptr);
}

static void dp_eal_cleanup()
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
		dp_grpc_thread_cancel();
	}
}

static int init_interfaces()
{
	int pf0_socket;

	dp_multipath_init();

	pf0_socket = rte_eth_dev_socket_id(dp_port_get_pf0_id());
	if (DP_FAILED(pf0_socket)) {
		DPS_LOG_ERR("Cannot get numa socket for pf0 port %d %s", dp_port_get_pf0_id(), dp_strerror(pf0_socket));
		return DP_ERROR;
	}

	if (DP_FAILED(dp_ports_init())
#ifdef ENABLE_VIRTSVC
		|| DP_FAILED(dp_virtsvc_init(pf0_socket))
#endif
		|| DP_FAILED(dp_graph_init()))
		return DP_ERROR;

	// VFs are started by GRPC later
	if (DP_FAILED(dp_port_start(dp_port_get_pf0_id()))
		|| DP_FAILED(dp_port_start(dp_port_get_pf1_id())))
		return DP_ERROR;

	if (DP_FAILED(dp_flow_init(pf0_socket))
		|| DP_FAILED(dp_nat_init(pf0_socket))
		|| DP_FAILED(dp_lb_init(pf0_socket))
		|| DP_FAILED(dp_lpm_init(pf0_socket))
		|| DP_FAILED(dp_alias_init(pf0_socket)))
		return DP_ERROR;

	return DP_OK;
}

static void free_interfaces()
{
#ifdef ENABLE_VIRTSVC
	dp_virtsvc_free();
#endif
	// TODO(plague): free graph once that code is refactored
	dp_ports_free();
}

static inline int run_dpdk_service()
{
	int result;

	if (DP_FAILED(init_interfaces()))
		return DP_ERROR;

	if (DP_FAILED(dp_grpc_thread_start()))
		return DP_ERROR;

	result = dp_dpdk_main_loop();

	if (DP_FAILED(dp_grpc_thread_join()))
		result = DP_ERROR;

	free_interfaces();

	return result;
}

static int run_service()
{
	int result;

	// pre-init sanity checks
	if (!dp_conf_is_conntrack_enabled() && dp_conf_is_offload_enabled()) {
		DP_EARLY_ERR("Disabled conntrack requires disabled offloading!");
		return DP_ERROR;
	}

	if (DP_FAILED(dp_log_init()))
		return DP_ERROR;

	dp_log_set_thread_name("control");
	DPS_LOG_INFO("Starting DP Service version %s", DP_SERVICE_VERSION);
	// from this point on, only DPS_LOG should be used

	if (signal(SIGINT, signal_handler) == SIG_ERR
		|| signal(SIGTERM, signal_handler) == SIG_ERR
	) {
		DPS_LOG_ERR("Cannot setup signal handling %s", dp_strerror(errno));
		return DP_ERROR;
	}

	if (DP_FAILED(dp_dpdk_layer_init()))
		return DP_ERROR;

	result = run_dpdk_service();

	dp_dpdk_layer_free();

	return result;
}

int main(int argc, char **argv)
{
	int retval = EXIT_SUCCESS;
	int eal_argcount;
	enum dp_conf_runmode runmode;

	// Read the config file first because it can contain EAL arguments
	// (those need to be injected *before* rte_eal_init())
	if (DP_FAILED(dp_conf_parse_file(getenv("DP_CONF"))))
		return EXIT_FAILURE;

	eal_argcount = dp_eal_init(&argc, &argv);
	if (DP_FAILED(eal_argcount)) {
		DP_EARLY_ERR("Failed to initialize EAL");
		return EXIT_FAILURE;
	}

	runmode = dp_conf_parse_args(argc - eal_argcount, argv + eal_argcount);
	switch (runmode) {
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
