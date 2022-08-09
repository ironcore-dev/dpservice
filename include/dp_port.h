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
	uint8_t					link_status;
	uint8_t					peer_pf_hairpin_tx_rx_queue_offset;
	uint8_t					peer_pf_port_id;
};

bool dp_is_port_allocated(struct dp_dpdk_layer *dp_layer, int portid);
struct dp_port* dp_get_next_avail_vf_port(struct dp_dpdk_layer *dp_layer, dp_port_type type);
int dp_get_next_avail_vf_id(struct dp_dpdk_layer *dp_layer, dp_port_type type);
int dp_get_pf_port_id_with_name(struct dp_dpdk_layer *dp_layer, char* pf_name);
struct dp_port* dp_port_create(struct dp_dpdk_layer *dp_layer,
							   dp_port_type type);
int dp_port_init(struct dp_port* port, int port_id, 
				 struct dp_port_ext *port_details);
int dp_port_allocate(struct dp_dpdk_layer *dp_layer, int portid, struct dp_port_ext *port_ext,
					 dp_port_type type);
int dp_port_deallocate(struct dp_dpdk_layer *dp_layer, int portid);
void print_link_info(int port_id, char *out, size_t out_size);
void dp_port_exit();
struct dp_port* dp_get_vf_port_per_id(struct dp_dpdk_layer *dp_layer, int portid);

void dp_port_set_link_status(struct dp_dpdk_layer *dp_layer,int port_id, uint8_t status);
uint8_t dp_port_get_link_status(struct dp_dpdk_layer *dp_layer,int port_id);

#ifdef __cplusplus
}
#endif
#endif /* _DP_PORT_H_ */
