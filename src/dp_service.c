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

static char *generated_argv[6];


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

	if (DP_FAILED(dp_start_port(dp_get_port_by_pf_index(0))))
		return DP_ERROR;

	if (DP_FAILED(dp_start_port(dp_get_port_by_pf_index(1))))
		return DP_ERROR;

#ifdef ENABLE_PF1_PROXY
	if (DP_FAILED(dp_start_pf_proxy_tap_port()))
		return DP_ERROR;
#endif

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

	if (dp_conf_is_multiport_eswitch() && dp_conf_is_offload_enabled()) {
		DP_EARLY_ERR("HW offloading is currently not supported for multi-port eswitch mode");
		return DP_ERROR;
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

static void free_eal_args(char **eal_argv)
{
	for (size_t i = 0; i < RTE_DIM(generated_argv); ++i)
		free(generated_argv[i]);
	free(eal_argv);
}

static int create_eal_args(int argc, char **argv, int eal_args_index, int *eal_argc_ptr, char ***eal_argv_ptr)
{
	int eal_argc;
	char **eal_argv;
	int generated_argc;
	int genarg;
	int curarg = 0;

	// program name
	eal_argc = 1;

	// generated EAL arguments
	generated_argc = 0;
	if (*dp_conf_get_eal_a_pf0())
		generated_argc += 2;
	if (*dp_conf_get_eal_a_pf1())
		generated_argc += 2;
	if (dp_conf_is_pf1_proxy_enabled())
		generated_argc += 2;
	eal_argc += generated_argc;

	// user-provided EAL arguments
	if (eal_args_index >= 0 && eal_args_index < argc)
		eal_argc += argc - eal_args_index;

	eal_argv = (char **)calloc(eal_argc, sizeof(*eal_argv));
	if (!eal_argv) {
		DP_EARLY_ERR("Cannot allocate EAL argument array");
		return DP_ERROR;
	}

	// program name
	eal_argv[curarg++] = argv[0];

	// generated EAL arguments
	// (EAL can change argv, need to store the original pointers for freeing)
	genarg = 0;
	if (*dp_conf_get_eal_a_pf0()) {
		generated_argv[genarg++] = strdup("-a");
		generated_argv[genarg++] = strdup(dp_conf_get_eal_a_pf0());
	}
	if (*dp_conf_get_eal_a_pf1()) {
		generated_argv[genarg++] = strdup("-a");
		generated_argv[genarg++] = strdup(dp_conf_get_eal_a_pf1());
	}
	if (dp_conf_is_pf1_proxy_enabled()) {
		generated_argv[genarg++] = strdup("--vdev");
		generated_argv[genarg++] = strdup(dp_generate_eal_pf1_proxy_params());
	}
	for (int i = 0; i < generated_argc; ++i) {
		if (!generated_argv[i]) {
			DP_EARLY_ERR("Cannot allocate generated EAL arguments");
			free_eal_args(eal_argv);
			return DP_ERROR;
		}
		eal_argv[curarg++] = generated_argv[i];
	}

	// user-provided EAL arguments
	if (eal_args_index >= 0)
		for (int i = eal_args_index; i < argc; ++i)
			eal_argv[curarg++] = argv[i];

	*eal_argc_ptr = eal_argc;
	*eal_argv_ptr = eal_argv;
	return DP_OK;
}

static int run_eal_service(int argc, char **argv, int eal_args_index)
{
	int ret;

	// TODO this needs to be done differently:
	//  - create EAL argv
	//  - if positional_index valid, add more EAL args from command-line
	//  - watch out for nic_type!
	// --> actually just copy everytime, but add to it for mellanox?

	int eal_argc;
	char **eal_argv;

	// TODO yeah, just rewrite dp_eal_init I think...
	if (DP_FAILED(create_eal_args(argc, argv, eal_args_index, &eal_argc, &eal_argv)))
		return DP_ERROR;

	for (int i = 0; i < eal_argc; ++i)
		printf("\t%s\n", eal_argv[i]);

// 	free_eal_args(eal_argv);
// 	return DP_ERROR;

	int eal_argc2 = eal_argc;
	char **eal_argv2 = eal_argv;
	printf("%d %p\n", eal_argc2, eal_argv2);
	for (int i = 0; i < eal_argc2; ++i)
		printf("  %s\n", (eal_argv2)[i]);
	ret = rte_eal_init(eal_argc2, eal_argv2);
	if (DP_FAILED(ret)) {
		DP_EARLY_ERR("Failed to initialize EAL");
		// TODO better (maybe goto?) but if we're jumping, then unroll a few layers??
		free_eal_args(eal_argv);
		return ret;
	}

	ret = run_service();

	rte_eal_cleanup();
	free_eal_args(eal_argv);
	return ret;


/*
	if (eal_args_index >= 0 && eal_args_index < argc)
		eal_argc += argc - eal_args_index;


	// TODO add mellanox args
	printf("NEED %d\n", eal_argc);

	eal_argv = (char **)calloc(eal_argc, sizeof(*eal_argv));
	if (!eal_argv) {
		DP_EARLY_ERR("Cannot allocate EAL argument array");
		return DP_ERROR;
	}
	// TODO better uninit/checks
	eal_argv[0] = strdup(argv[0]);  // TODO dup not needed
	// TODO add mellanox args
	for (int i = 0; i < eal_argc-1; ++i)  // TODO hmm unclear -1
		eal_argv[1+i] = strdup(argv[eal_args_index+i]);  // TODO yes, checks

	for (int i = 0; i < eal_argc; ++i)
		printf("\t%s\n", eal_argv[i]);

	ret = rte_eal_init(eal_argc, eal_argv);  // TODO may modify!!!! (see the original code and comment then)
	if (DP_FAILED(ret)) {
		DP_EARLY_ERR("Failed to initialize EAL");
		// TODO free argv
		return ret;
	}

	ret = run_service();

	rte_eal_cleanup();
	free(eal_argv);
	return ret;
	// binary
	// (optional) -l <cores>
	// (optional) -a <from pf0>
	// (optional) -a <from pf1>
	// (optional) --vdev <pf1-tap>
	// (optional) <eal_argv>

	// TODO temporary, unsafe for -1!
	int eal_argc = argc - eal_args_index + 1;
	char **eal_argv = argv + eal_args_index -1;

	ret = dp_eal_init(&eal_argc, &eal_argv);
	if (DP_FAILED(ret)) {
		DP_EARLY_ERR("Failed to initialize EAL");
		return ret;
	}

	ret = run_service();

	dp_eal_cleanup();

	return ret;*/
}

int main(int argc, char **argv)
{
	int retval = EXIT_SUCCESS;
	int eal_args_index = -1;

	// Read the config file first so command-line arguments take precedence
	if (DP_FAILED(dp_conf_parse_file(getenv("DP_CONF"))))
		return EXIT_FAILURE;

	switch (dp_conf_parse_args(argc, argv, &eal_args_index)) {
	case DP_CONF_RUNMODE_ERROR:
		retval = EXIT_FAILURE;
		break;
	case DP_CONF_RUNMODE_EXIT:
		retval = EXIT_SUCCESS;
		break;
	case DP_CONF_RUNMODE_NORMAL:
		retval = DP_FAILED(run_eal_service(argc, argv, eal_args_index)) ? EXIT_FAILURE : EXIT_SUCCESS;
		break;
	}

	dp_conf_free();

	return retval;
}
