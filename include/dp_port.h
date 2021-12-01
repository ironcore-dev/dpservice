#ifndef _DP_PORT_H_
#define _DP_PORT_H_

#include <stdint.h>
#include <inttypes.h>
#include <net/if.h>

#include <rte_ethdev.h>
#include <rte_graph.h>

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
	char					node_name[RTE_NODE_NAMESIZE];
};

struct dp_port* dp_get_next_avail_vf_port(struct dp_dpdk_layer *dp_layer, dp_port_type type);
int dp_get_next_avail_vf_id(struct dp_dpdk_layer *dp_layer, dp_port_type type);
int dp_get_pf_port_id_with_name(struct dp_dpdk_layer *dp_layer, char* pf_name);
struct dp_port* dp_port_create(struct dp_dpdk_layer *dp_layer,
							   dp_port_type type);
int dp_port_init(struct dp_port* port, int p_port_id, int port_id, 
				 struct dp_port_ext *port_details);
int dp_port_allocate(struct dp_dpdk_layer *dp_layer, struct dp_port_ext *port_ext,
					 dp_port_type type);
void dp_port_exit();

#ifdef __cplusplus
}
#endif
#endif /* _DP_PORT_H_ */
