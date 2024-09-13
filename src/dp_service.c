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
#include "rte_flow/dp_rte_async_flow_isolation.h"

static char **dp_argv;
static int dp_argc;
static char *dp_mlx_args[4];

struct rte_mempool *test_mempool;

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
	dp_mlx_args[2] = dp_argv[curarg++] = strdup("");
	dp_mlx_args[3] = dp_argv[curarg++] = strdup("");
	if (!dp_mlx_args[0] || !dp_mlx_args[1] || !dp_mlx_args[2] || !dp_mlx_args[3]) {
		DP_EARLY_ERR("Cannot allocate Mellanox arguments");
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

static void dp_args_free_mellanox(void)
{
	for (int i = 0; i < 4; ++i)
		free(dp_mlx_args[i]);
	free(dp_argv);
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

bool stop = false;
static void signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
		// this is specifically printf() to communicate with the sender
		printf("\n\nSignal %d received, preparing to exit...\n", signum);
		dp_force_quit();
		stop = true;
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

	int ret;
	ret = rte_eth_dev_start(0);
	if (DP_FAILED(ret)) {
		DPS_LOG_ERR("Cannot start ethernet port", DP_LOG_PORTID(0), DP_LOG_RET(ret));
		return ret;
	}
	ret = rte_eth_dev_start(1);
	if (DP_FAILED(ret)) {
		DPS_LOG_ERR("Cannot start ethernet port", DP_LOG_PORTID(1), DP_LOG_RET(ret));
		return ret;
	}
	ret = rte_eth_dev_start(6);
	if (DP_FAILED(ret)) {
		DPS_LOG_ERR("Cannot start ethernet port", DP_LOG_PORTID(6), DP_LOG_RET(ret));
		return ret;
	}
	ret = rte_eth_dev_stop(6);
	if (DP_FAILED(ret)) {
		DPS_LOG_ERR("Cannot stop ethernet port", DP_LOG_PORTID(6), DP_LOG_RET(ret));
		return ret;
	}
	ret = rte_eth_dev_stop(1);
	if (DP_FAILED(ret)) {
		DPS_LOG_ERR("Cannot stop ethernet port", DP_LOG_PORTID(1), DP_LOG_RET(ret));
		return ret;
	}
	ret = rte_eth_dev_stop(0);
	if (DP_FAILED(ret)) {
		DPS_LOG_ERR("Cannot stop ethernet port", DP_LOG_PORTID(0), DP_LOG_RET(ret));
		return ret;
	}

	DP_FOREACH_PORT(&_dp_ports, port) {
		if (DP_FAILED(dp_configure_async_flows(port->port_id)))
			rte_panic("failed\n");
	}

	if (DP_FAILED(dp_start_port(dp_get_port_by_pf_index(0))))
		return DP_ERROR;

	if (DP_FAILED(dp_start_port(dp_get_port_by_pf_index(1))))
		return DP_ERROR;

#ifdef ENABLE_PF1_PROXY
	if (DP_FAILED(dp_start_pf_proxy_tap_port()))
		return DP_ERROR;
#endif

	ret = rte_eth_dev_start(6);
	if (DP_FAILED(ret)) {
		DPS_LOG_ERR("Cannot start ethernet port", DP_LOG_PORTID(6), DP_LOG_RET(ret));
		return ret;
	}

	dp_async_test();

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

static int init_ethdev(uint16_t port_id, struct rte_eth_dev_info *dev_info)
{
	int socket_id = rte_eth_dev_socket_id(port_id);
	struct rte_eth_txconf txq_conf;
	struct rte_eth_rxconf rxq_conf;
	struct rte_eth_conf port_conf = { .rxmode = { .mq_mode = RTE_ETH_MQ_RX_NONE, }, };
	int ret;

	/* Default config */
	port_conf.txmode.offloads &= dev_info->tx_offload_capa;

	ret = rte_eth_dev_configure(port_id, 1, 1, &port_conf);
	if (DP_FAILED(ret)) {
		DPS_LOG_ERR("Cannot configure ethernet device", DP_LOG_PORTID(port_id), DP_LOG_RET(ret));
		return DP_ERROR;
	}

	txq_conf = dev_info->default_txconf;
	txq_conf.offloads = port_conf.txmode.offloads;

	ret = rte_eth_tx_queue_setup(port_id, 0, 256, socket_id, &txq_conf);
	if (DP_FAILED(ret)) {
		DPS_LOG_ERR("Tx queue setup failed", DP_LOG_PORTID(port_id), DP_LOG_RET(ret));
		return DP_ERROR;
	}

	rxq_conf = dev_info->default_rxconf;
	rxq_conf.offloads = port_conf.rxmode.offloads;

	ret = rte_eth_rx_queue_setup(port_id, 0, 256, socket_id, &rxq_conf, test_mempool);
	if (DP_FAILED(ret)) {
		DPS_LOG_ERR("Rx queue setup failed", DP_LOG_PORTID(port_id), DP_LOG_RET(ret));
		return DP_ERROR;
	}

	ret = rte_eth_promiscuous_enable(port_id);
	if (DP_FAILED(ret)) {
		DPS_LOG_ERR("Promiscuous mode setting failed", DP_LOG_PORTID(port_id), DP_LOG_RET(ret));
		return DP_ERROR;
	}

	return DP_OK;
}

static int init_port(uint16_t port_id)
{
	struct rte_eth_dev_info dev_info;
	int ret;

	ret = rte_eth_dev_info_get(port_id, &dev_info);
	if (DP_FAILED(ret)) {
		DPS_LOG_ERR("Cannot get device info", DP_LOG_PORTID(port_id), DP_LOG_RET(ret));
		return DP_ERROR;
	}

	return init_ethdev(port_id, &dev_info);
}

static int configure_flows(uint16_t port_id)
{
	static const struct rte_flow_port_attr port_attr = {
		.nb_counters = 0,
		.nb_aging_objects = 0,
		.nb_meters = 0,
		.flags = 0,
	};
	static const struct rte_flow_queue_attr queue_attr = {
		.size = 64,
	};
	const struct rte_flow_queue_attr *attr_list[1];
	struct rte_flow_error error;
	int ret;

	attr_list[0] = &queue_attr;

	ret = rte_flow_configure(port_id, &port_attr, 1, attr_list, &error);
	if (DP_FAILED(ret))
		DPS_LOG_ERR("Failed to configure port's queue attr",
					DP_LOG_PORTID(port_id), DP_LOG_RET(ret), DP_LOG_FLOW_ERROR(error.message));

	return ret;
}

static int isolate(uint16_t port_id)
{
	struct rte_flow_error error;
	int ret;

	ret = rte_flow_isolate(port_id, 1, &error);
	if (DP_FAILED(ret))
		DPS_LOG_ERR("Flows cannot be isolated", DP_LOG_PORTID(port_id), DP_LOG_FLOW_ERROR(error.message), DP_LOG_RET(ret));
	return ret;
}

static int negotiate(uint16_t port_id)
{
	uint64_t rx_meta_features = 0;
	int ret;

	rx_meta_features |= RTE_ETH_RX_METADATA_USER_FLAG;
	rx_meta_features |= RTE_ETH_RX_METADATA_USER_MARK;
	rx_meta_features |= RTE_ETH_RX_METADATA_TUNNEL_ID;

	ret = rte_eth_rx_metadata_negotiate(port_id, &rx_meta_features);
	if (ret == 0) {
		if (!(rx_meta_features & RTE_ETH_RX_METADATA_USER_FLAG))
			DPS_LOG_WARNING("Flow action FLAG will not affect Rx mbufs", DP_LOG_PORTID(port_id));
		if (!(rx_meta_features & RTE_ETH_RX_METADATA_USER_MARK))
			DPS_LOG_WARNING("Flow action MARK will not affect Rx mbufs", DP_LOG_PORTID(port_id));
		if (!(rx_meta_features & RTE_ETH_RX_METADATA_TUNNEL_ID))
			DPS_LOG_WARNING("Flow tunnel offload support might be limited or unavailable", DP_LOG_PORTID(port_id));
	} else if (ret != -ENOTSUP) {
		DPS_LOG_ERR("Error when negotiating Rx meta features", DP_LOG_PORTID(port_id), DP_LOG_RET(ret));
	}

	return ret;
}

static int run_test(void)
{
	int ret;

	if (DP_FAILED(negotiate(0))
		|| DP_FAILED(negotiate(1))
		|| DP_FAILED(negotiate(6)))
		return DP_ERROR;

	if (DP_FAILED(isolate(0)))
		return DP_ERROR;
	if (DP_FAILED(isolate(1)))
		return DP_ERROR;
	if (DP_FAILED(isolate(6)))
		return DP_ERROR;

	test_mempool = rte_pktmbuf_pool_create("test_mbuf_pool", DP_MBUF_POOL_SIZE,
												   DP_MEMPOOL_CACHE_SIZE, DP_MBUF_PRIV_DATA_SIZE,
												   (9118 + RTE_PKTMBUF_HEADROOM),
												   -1);

	ret = init_port(0);
	if (DP_FAILED(ret)) {
		DPS_LOG_ERR("Cannot init ethernet port", DP_LOG_PORTID(0), DP_LOG_RET(ret));
		return ret;
	}
	ret = rte_eth_dev_start(0);
	if (DP_FAILED(ret)) {
		DPS_LOG_ERR("Cannot start ethernet port", DP_LOG_PORTID(0), DP_LOG_RET(ret));
		return ret;
	}

	ret = init_port(1);
	if (DP_FAILED(ret)) {
		DPS_LOG_ERR("Cannot init ethernet port", DP_LOG_PORTID(1), DP_LOG_RET(ret));
		return ret;
	}
	ret = rte_eth_dev_start(1);
	if (DP_FAILED(ret)) {
		DPS_LOG_ERR("Cannot start ethernet port", DP_LOG_PORTID(1), DP_LOG_RET(ret));
		return ret;
	}

	ret = init_port(6);
	if (DP_FAILED(ret)) {
		DPS_LOG_ERR("Cannot init ethernet port", DP_LOG_PORTID(0), DP_LOG_RET(ret));
		return ret;
	}
	ret = rte_eth_dev_start(6);
	if (DP_FAILED(ret)) {
		DPS_LOG_ERR("Cannot start ethernet port", DP_LOG_PORTID(6), DP_LOG_RET(ret));
		return ret;
	}

	ret = rte_eth_dev_stop(0);
	if (DP_FAILED(ret)) {
		DPS_LOG_ERR("Cannot stop ethernet port", DP_LOG_PORTID(0), DP_LOG_RET(ret));
		return ret;
	}
	ret = rte_eth_dev_stop(1);
	if (DP_FAILED(ret)) {
		DPS_LOG_ERR("Cannot stop ethernet port", DP_LOG_PORTID(1), DP_LOG_RET(ret));
		return ret;
	}
	ret = rte_eth_dev_stop(6);
	if (DP_FAILED(ret)) {
		DPS_LOG_ERR("Cannot stop ethernet port", DP_LOG_PORTID(6), DP_LOG_RET(ret));
		return ret;
	}

	ret = configure_flows(0);
	if (DP_FAILED(ret)) {
		DPS_LOG_ERR("Cannot configure flows", DP_LOG_PORTID(0), DP_LOG_RET(ret));
		return ret;
	}
	ret = configure_flows(1);
	if (DP_FAILED(ret)) {
		DPS_LOG_ERR("Cannot configure flows", DP_LOG_PORTID(1), DP_LOG_RET(ret));
		return ret;
	}
	ret = configure_flows(6);
	if (DP_FAILED(ret)) {
		DPS_LOG_ERR("Cannot configure flows", DP_LOG_PORTID(6), DP_LOG_RET(ret));
		return ret;
	}

	ret = rte_eth_dev_start(0);
	if (DP_FAILED(ret)) {
		DPS_LOG_ERR("Cannot start ethernet port", DP_LOG_PORTID(0), DP_LOG_RET(ret));
		return ret;
	}
	ret = rte_eth_dev_start(1);
	if (DP_FAILED(ret)) {
		DPS_LOG_ERR("Cannot start ethernet port", DP_LOG_PORTID(1), DP_LOG_RET(ret));
		return ret;
	}
	ret = rte_eth_dev_start(6);
	if (DP_FAILED(ret)) {
		DPS_LOG_ERR("Cannot start ethernet port", DP_LOG_PORTID(6), DP_LOG_RET(ret));
		return ret;
	}

	struct test_default_async_rules default_async_rules = {0};
	if (DP_FAILED(dp_create_pf_async_isolation_templates_proxy(0, &default_async_rules)))
		return DP_ERROR;

	if (DP_FAILED(dp_create_pf_async_isolation_rules_test(&default_async_rules)))
		return DP_ERROR;

	FILE *file = stdout;
	struct rte_flow_error error;
	ret = rte_flow_dev_dump(0, NULL, file, &error);
	if (DP_FAILED(ret)) {
		DPS_LOG_ERR("Failed to dump rte async flow rules",
					DP_LOG_PORTID(0), DP_LOG_RET(ret), DP_LOG_FLOW_ERROR(error.message));
		return ret;
	}

	printf("All ok, entering loop\n");
	while (!stop) {
		sleep(1);
	}

	return DP_OK;
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
		/*|| DP_FAILED(dp_dpdk_layer_init())*/)
		return DP_ERROR;

	result = run_test();

// 	result = run_dpdk_service();

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
