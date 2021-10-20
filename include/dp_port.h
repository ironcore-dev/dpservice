#ifndef _DP_PORT_H_
#define _DP_PORT_H_

#include <stdint.h>
#include <inttypes.h>
#include <net/if.h>

#include <rte_ethdev.h>

#include "dpdk_layer.h"
#include "handler.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	DP_PORT_PF,
	DP_PORT_VF,
} dp_port_type;

struct dp_port_ext {
	char					port_name[IFNAMSIZ];
	struct rte_ether_addr	port_mac;
	int						port_mtu;
	uint8_t					underlay_ipv6_addr[16];
};

struct dp_port {
	struct dp_dpdk_layer	*dp_layer;
	dp_port_type			dp_p_type;
	int						dp_p_port_id;
	int						dp_port_id;
	int						dp_allocated;
	uint8_t 				vf_name[IFNAMSIZ];
	struct dp_port_ext		dp_port_ext;
	struct port_handler 	*handlers[DP_MAX_HANDLER];
	int						dp_handler_cnt;
};

struct dp_port* get_dp_vf_port_with_id(int port_id,
									   struct dp_dpdk_layer *dp_layer);
void dp_port_add_handler(struct port_handler* h, int port_id,
						 struct dp_dpdk_layer *dp_layer);
struct dp_port* dp_port_create(struct dp_dpdk_layer *dp_layer,
							   dp_port_type type);
int dp_port_init(struct dp_port* port, int p_port_id, int port_id, 
				 struct dp_port_ext *port_details);
void dp_port_allocate(struct dp_port* port);
void dp_port_exit();

#ifdef __cplusplus
}
#endif
#endif /* _DP_PORT_H_ */
