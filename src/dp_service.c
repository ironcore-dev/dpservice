#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <sys/queue.h>

#include "dpdk_layer.h"

/* Dummy function to configure the data plane hard-coded
 * TODO: This should be done via some kind of RPC mechanism*/
#define DP_PF_NAME	"enp59s0f0"
#define DP_PF_MAC	0x43f72e8dead
void dp_hard_configure()
{
	struct dp_port_ext pf_port;
	long int mac = DP_PF_MAC;
	int ret;

	memset(&pf_port, 0, sizeof(pf_port));
	memcpy(pf_port.port_name, DP_PF_NAME, strlen(DP_PF_NAME));
	memcpy(pf_port.port_mac.addr_bytes, &mac, sizeof(mac));
	pf_port.port_mtu = 9100;
	dp_prepare(&pf_port, 1);
	ret = dp_allocate_vf(0);
	dp_configure_vf(ret);
}

int main(int argc, char **argv)
{
	dp_dpdk_init(argc, argv);
	
	/* Test */
	dp_hard_configure();
	/* Test */

	dp_dpdk_main_loop();
	dp_dpdk_exit();

	return 0;
}
