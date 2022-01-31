#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <pthread.h>
#include <sys/queue.h>

#include "dpdk_layer.h"
#include "dp_util.h"
#include "dp_flow.h"
#include "dp_lpm.h"
#include "dp_grpc_service.h"

static void *dp_handle_grpc(__rte_unused void *arg)
{
	GRPCService *grpc_svc = new GRPCService(get_dpdk_layer());

	grpc_svc->run("[::]:1337");

	delete grpc_svc;

	return NULL;
}


static void dp_init_interfaces()
{
	struct dp_port_ext pf0_port, pf1_port, vf_port;
	int i;

	memset(&pf0_port, 0, sizeof(pf0_port));
	memset(&pf1_port, 0, sizeof(pf1_port));
	memset(&vf_port, 0, sizeof(vf_port));

	/* Init the PFs which were received via command line */
	memcpy(pf0_port.port_name, dp_get_pf0_name(), IFNAMSIZ);
	dp_init_interface(&pf0_port, DP_PORT_PF);

	memcpy(pf1_port.port_name, dp_get_pf1_name(), IFNAMSIZ);
	dp_init_interface(&pf1_port, DP_PORT_PF);

	memcpy(vf_port.port_name, dp_get_vf_pattern(), IFNAMSIZ);

	/* Only init the max. possible VFs, GRPC will kick them off later */
	for (i = 0; i < DP_ACTIVE_VF_PORT; i++)
		dp_init_interface(&vf_port, DP_PORT_VF);

	dp_init_graph();
	dp_start_interface(&pf0_port, DP_PORT_PF);
	dp_start_interface(&pf1_port, DP_PORT_PF);
	dp_init_flowtable(rte_eth_dev_socket_id(dp_get_pf0_port_id()));
	dp_init_vm_handle_tbl(rte_eth_dev_socket_id(dp_get_pf0_port_id()));
}

int main(int argc, char **argv)
{
	int ret;

	ret = dp_dpdk_init(argc, argv);
	argc -= ret;
	argv += ret;

	ret = dp_parse_args(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid dp_service parameters\n");

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
