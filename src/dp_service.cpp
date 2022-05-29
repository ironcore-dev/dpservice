#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <pthread.h>
#include <sys/queue.h>

#include "dpdk_layer.h"
#include "dp_util.h"
#include "dp_flow.h"
#include "dp_version.h"
#include "dp_lpm.h"
#include "dp_nat.h"
#include "dp_lb.h"
#include "grpc/dp_grpc_service.h"
#include "dp_multi_path.h"

static void *dp_handle_grpc(__rte_unused void *arg)
{
	GRPCService *grpc_svc = new GRPCService();

	grpc_svc->run("[::]:1337");

	delete grpc_svc;

	return NULL;
}

static void dp_init_interfaces()
{
	struct dp_port_ext pf0_port, pf1_port, vf_port;
	int i, active_vfs;

	memset(&pf0_port, 0, sizeof(pf0_port));
	memset(&pf1_port, 0, sizeof(pf1_port));
	memset(&vf_port, 0, sizeof(vf_port));

	/* Init the PFs which were received via command line */
	memcpy(pf0_port.port_name, dp_get_pf0_name(), IFNAMSIZ);
	dp_init_interface(&pf0_port, DP_PORT_PF);

	memcpy(pf1_port.port_name, dp_get_pf1_name(), IFNAMSIZ);
	dp_init_interface(&pf1_port, DP_PORT_PF);

	memcpy(vf_port.port_name, dp_get_vf_pattern(), IFNAMSIZ);

	active_vfs = dp_get_num_of_vfs();
	if (active_vfs > DP_MAX_VF_PRO_PORT)
		rte_exit(EXIT_FAILURE, "In kernel %d VFs defined but we support max %d.\n",
				 active_vfs, DP_MAX_VF_PRO_PORT);
	/* Only init the max. possible VFs, GRPC will kick them off later */
	for (i = 0; i < active_vfs; i++)
		dp_init_interface(&vf_port, DP_PORT_VF);

	dp_init_graph();
	dp_start_interface(&pf0_port, dp_get_pf0_port_id(), DP_PORT_PF);
	dp_start_interface(&pf1_port, dp_get_pf1_port_id(), DP_PORT_PF);
	dp_init_flowtable(rte_eth_dev_socket_id(dp_get_pf0_port_id()));
	dp_init_nat_tables(rte_eth_dev_socket_id(dp_get_pf0_port_id()));
	dp_init_lb_tables(rte_eth_dev_socket_id(dp_get_pf0_port_id()));
	dp_init_vm_handle_tbl(rte_eth_dev_socket_id(dp_get_pf0_port_id()));
	if (dp_is_wcmp_enabled())
		fill_port_select_table(dp_get_wcmp_frac());
}

int main(int argc, char **argv)
{
	int ret;

	printf("Starting DP Service version %s\n", DP_SERVICE_VERSION);
	ret = dp_dpdk_init(argc, argv);
	argc -= ret;
	argv += ret;

	ret = dp_parse_args(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid dp_service parameters\n");

	if (!dp_is_conntrack_enabled() && dp_is_offload_enabled())
		rte_exit(EXIT_FAILURE, "Disabled conntrack requires disabled offloading !\n");

	dp_init_interfaces();

	ret = rte_ctrl_thread_create(dp_get_ctrl_thread_id(), "grpc-thread", NULL,
							dp_handle_grpc, NULL);
	if (ret < 0)
		rte_exit(EXIT_FAILURE,
				"Cannot create grpc thread\n");

	dp_dpdk_main_loop();

	pthread_join(*dp_get_ctrl_thread_id(), NULL);

	dp_dpdk_exit();

	return 0;
}
