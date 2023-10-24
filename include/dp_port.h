#ifndef _DP_PORT_H_
#define _DP_PORT_H_

#include <stdint.h>
#include <stdbool.h>
#include <net/if.h>
#include <rte_pci.h>

#ifdef __cplusplus
extern "C" {
#endif

// strangely this is never done by DPDK in general, only in specific headers
#define DP_INVALID_PORT_ID UINT16_MAX

#define DP_MAX_PF_PORTS 2
#define DP_MAX_VF_PORTS 126
#define DP_MAX_PORTS    (DP_MAX_PF_PORTS + DP_MAX_VF_PORTS)

enum dp_port_type {
	DP_PORT_PF,
	DP_PORT_VF,
};

enum dp_vf_port_attach_status {
	DP_VF_PORT_DETACHED,
	DP_VF_PORT_ATTACHED,
};

struct dp_port {
	enum dp_port_type				port_type;
	uint16_t						port_id;
	char							port_name[IF_NAMESIZE];
	uint8_t							link_status;
	bool							allocated;
	char							vf_name[IF_NAMESIZE];
	uint8_t							peer_pf_hairpin_tx_rx_queue_offset;
	uint16_t						peer_pf_port_id;
	enum dp_vf_port_attach_status	attach_status;
	struct rte_flow					*default_flow;
};

struct dp_ports {
	struct dp_port *ports;
	struct dp_port *end;
};

struct dp_ports *get_dp_ports(void);

struct dp_port *dp_port_get(uint16_t port_id);
struct dp_port *dp_port_get_vf(uint16_t port_id);
int dp_port_set_link_status(uint16_t port_id, uint8_t status);
uint8_t dp_port_get_link_status(uint16_t port_id);
int dp_port_set_vf_attach_status(uint16_t port_id, enum dp_vf_port_attach_status status);
enum dp_vf_port_attach_status dp_port_get_vf_attach_status(uint16_t port_id);
bool dp_port_is_vf_free(uint16_t port_id);
uint16_t dp_port_get_free_vf_port_id(void);

int dp_ports_init(void);
void dp_ports_free(void);

uint16_t dp_port_get_pf0_id(void);
uint16_t dp_port_get_pf1_id(void);
bool dp_port_is_pf(uint16_t port_id);

int dp_port_start(uint16_t port_id);
int dp_port_stop(uint16_t port_id);

#define DP_FOREACH_PORT(DP_PORTS, VARNAME) \
	for (struct dp_port *VARNAME = (DP_PORTS)->ports; \
		 VARNAME < (DP_PORTS)->end; \
		 ++VARNAME)

#ifdef __cplusplus
}
#endif
#endif /* _DP_PORT_H_ */
