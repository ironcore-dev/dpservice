#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <pthread.h>
#include <sys/queue.h>

#include "dp_error.h"
#include "dp_conf.h"
#include "dpdk_layer.h"
#include "dp_util.h"
#include "dp_flow.h"
#include "dp_version.h"
#include "dp_lpm.h"
#include "dp_nat.h"
#include "dp_lb.h"
#include "dp_alias.h"
#include "grpc/dp_grpc_service.h"
#include "dp_multi_path.h"
#include "dp_log.h"

static char **dp_argv;
static int dp_argc;
static char *dp_mlx_args[4];

static inline char *safe_strdup(const char *str)
{
	char *dup = strdup(str);
	if (!dup)
		rte_exit(EXIT_FAILURE, "Cannot duplicate argument\n");
	return dup;
}

static void dp_args_add_mellanox(int *orig_argc, char ***orig_argv)
{
	int i;
	int argend = -1;
	int argc = *orig_argc;
	char **argv = *orig_argv;

	// will be adding two devices (4 args) + terminator
	dp_argv = (char **)calloc(argc + 5, sizeof(*dp_argv));
	if (!dp_argv)
		rte_exit(EXIT_FAILURE, "Cannot allocate argument array\n");

	// copy EAL args
	for (i = 0; i < argc; i++) {
		if (strcmp(argv[i], "--") == 0) {
			argend = i;
			break;
		} else {
			dp_argv[i] = argv[i];
		}
	}
	// add mellanox args (remember that they can be written to, so strdup())
	dp_mlx_args[0] = dp_argv[i++] = safe_strdup("-a");
	dp_mlx_args[1] = dp_argv[i++] = safe_strdup(dp_conf_get_eal_a_pf0());
	dp_mlx_args[2] = dp_argv[i++] = safe_strdup("-a");
	dp_mlx_args[3] = dp_argv[i++] = safe_strdup(dp_conf_get_eal_a_pf1());
	// add original dp_service args
	if (argend >= 0) {
		for (int j = argend; j < argc; ++j)
			dp_argv[i++] = argv[j];
	}
	dp_argv[i] = NULL;
	dp_argc = i;

	*orig_argc = dp_argc;
	*orig_argv = dp_argv;
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
		dp_args_add_mellanox(argc_ptr, argv_ptr);
	return rte_eal_init(*argc_ptr, *argv_ptr);
}

static void dp_eal_cleanup()
{
	rte_eal_cleanup();
	if (dp_is_mellanox_opt_set())
		dp_args_free_mellanox();
}


static void dp_init_interfaces()
{
	struct dp_port_ext pf0_port, pf1_port, vf_port;
	int i, active_vfs;

	memset(&pf0_port, 0, sizeof(pf0_port));
	memset(&pf1_port, 0, sizeof(pf1_port));
	memset(&vf_port, 0, sizeof(vf_port));

	/* Init the PFs which were received via command line */
	// TODO(plague) use strcpy, size of name from conf is not known here
	memcpy(pf0_port.port_name, dp_conf_get_pf0_name(), IFNAMSIZ);
	dp_init_interface(&pf0_port, DP_PORT_PF);

	memcpy(pf1_port.port_name, dp_conf_get_pf1_name(), IFNAMSIZ);
	dp_init_interface(&pf1_port, DP_PORT_PF);

	memcpy(vf_port.port_name, dp_conf_get_vf_pattern(), IFNAMSIZ);

	active_vfs = dp_get_num_of_vfs();
	if (active_vfs > DP_MAX_VF_PRO_PORT)
		rte_exit(EXIT_FAILURE, "In kernel %d VFs defined but we support max %d.\n",
				 active_vfs, DP_MAX_VF_PRO_PORT);
	/* Only init the max. possible VFs, GRPC will kick them off later */
	for (i = 0; i < active_vfs; i++)
		dp_init_interface(&vf_port, DP_PORT_VF);
	
	if (dp_conf_is_offload_enabled())
		hairpin_vfs_to_pf();

	// TODO(plague): proper refactoring in a follow-up PR
	if (dp_init_graph() != 0)
		rte_exit(EXIT_FAILURE, "Cannot initialize graph subsystem\n");
	dp_start_interface(&pf0_port, dp_get_pf0_port_id(), DP_PORT_PF);
	dp_start_interface(&pf1_port, dp_get_pf1_port_id(), DP_PORT_PF);
	dp_init_flowtable(rte_eth_dev_socket_id(dp_get_pf0_port_id()));
	dp_init_nat_tables(rte_eth_dev_socket_id(dp_get_pf0_port_id()));
	dp_init_lb_tables(rte_eth_dev_socket_id(dp_get_pf0_port_id()));
	dp_init_vm_handle_tbl(rte_eth_dev_socket_id(dp_get_pf0_port_id()));
	dp_init_alias_handle_tbl(rte_eth_dev_socket_id(dp_get_pf0_port_id()));
	if (dp_conf_is_wcmp_enabled())
		fill_port_select_table(dp_conf_get_wcmp_frac());
}

static void *dp_handle_grpc(__rte_unused void *arg)
{
	GRPCService *grpc_svc = new GRPCService();
	grpc_svc->run("[::]:1337");
	delete grpc_svc;
	return NULL;
}

static int run_threads()
{
	if (rte_ctrl_thread_create(dp_get_ctrl_thread_id(), "grpc-thread", NULL, dp_handle_grpc, NULL)) {
		DPS_LOG_ERR("Cannot create grpc thread");
		return EXIT_FAILURE;
	}

	dp_dpdk_main_loop();

	pthread_join(*dp_get_ctrl_thread_id(), NULL);

	return EXIT_SUCCESS;
}

static int run_service()
{
	int retval;

	if (!dp_conf_is_conntrack_enabled() && dp_conf_is_offload_enabled()) {
		fprintf(stderr, "Disabled conntrack requires disabled offloading!\n");
		return EXIT_FAILURE;
	}

	dp_log_init();
	dp_log_set_thread_name("control");
	DPS_LOG_INFO("Starting DP Service version %s", DP_SERVICE_VERSION);
	// from this point on, only DPS_LOG should be used

	dp_dpdk_init();
	// TODO retval not implemented

	dp_init_interfaces();
	// TODO retval not implemented

	retval = run_threads();

	dp_dpdk_exit();

	return retval;
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
	if (eal_argcount < 0) {
		fprintf(stderr, "Failed to initialize EAL\n");
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
		retval = run_service();
		break;
	}

	dp_eal_cleanup();

	return retval;
}
