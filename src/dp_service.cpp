#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <sys/queue.h>

#include "dpdk_layer.h"
#include "dp_util.h"
#include "dp_grpc_service.h"

/* Dummy function to configure the data plane hard-coded
 * TODO: This should be done via some kind of RPC mechanism*/
#define DP_PF_MAC	0x43f72e8dead
#define DP_PF_MAC_1	0x43f72e8cfca

static void *dp_handle_grpc(__rte_unused void *arg)
{
	GRPCService *grpc_svc = new GRPCService(get_dpdk_layer());

	grpc_svc->run("[::]:1337");

	delete grpc_svc;

	return NULL;
}


static void dp_init_pfs()
{
	struct dp_port_ext pf_port;
	long int mac = DP_PF_MAC;

	memset(&pf_port, 0, sizeof(pf_port));
	memcpy(pf_port.port_name, dp_get_pf0_name(), IFNAMSIZ);
	memcpy(pf_port.port_mac.addr_bytes, &mac, sizeof(mac));
	pf_port.port_mtu = 9100;
	dp_init_interface(&pf_port, DP_PORT_PF);
	memcpy(pf_port.port_name, dp_get_pf1_name(), IFNAMSIZ);
	dp_init_interface(&pf_port, DP_PORT_PF);

	memcpy(pf_port.port_name, dp_get_pf0_name(), IFNAMSIZ);
	dp_init_interface(&pf_port, DP_PORT_VF);

	memcpy(pf_port.port_name, dp_get_pf0_name(), IFNAMSIZ);
	dp_init_interface(&pf_port, DP_PORT_VF);
	dp_init_graph();
}

int main(int argc, char **argv)
{
	static pthread_t tid;
	int ret;

	ret = dp_dpdk_init(argc, argv);
	argc -= ret;
	argv += ret;

	ret = dp_parse_args(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid dp_service parameters\n");

	dp_init_pfs();

	ret = rte_ctrl_thread_create(&tid, "grpc-thread", NULL,
							dp_handle_grpc, NULL);
	if (ret < 0)
			rte_exit(EXIT_FAILURE,
					"Cannot create grpc thread\n");

	dp_dpdk_main_loop();

	dp_dpdk_exit();

	return 0;
}
