#ifndef __DP_PORT_H__
#define __DP_PORT_H__

#include <stdint.h>
#include <stdbool.h>
#include <net/if.h>
#include <rte_pci.h>
#include "dp_internal_stats.h"
#include "dp_lpm.h"
#include "dpdk_layer.h"

#ifdef __cplusplus
extern "C" {
#endif

enum dp_port_type {
	DP_PORT_PF,
	DP_PORT_VF,
};

struct dp_port {
	enum dp_port_type				port_type;
	uint16_t						port_id;
	char							port_name[IF_NAMESIZE];
	int								socket_id;
	uint8_t							link_status;
	bool							allocated;
	char							vf_name[IF_NAMESIZE];
	uint8_t							peer_pf_hairpin_tx_rx_queue_offset;
	uint16_t						peer_pf_port_id;
	bool							attached;
	struct vm_entry					vm;
	struct rte_flow					*default_jump_flow;
	struct rte_flow					*default_capture_flow;
	bool							captured;
	struct dp_port_stats			stats;
};

struct dp_ports {
	struct dp_port *ports;
	struct dp_port *end;
};

struct dp_ports *dp_get_ports(void);

struct dp_port *dp_get_port(uint16_t port_id);

struct dp_port *dp_get_port_by_name(const char *pci_name);

bool dp_port_is_pf(uint16_t port_id);

int dp_attach_vf(uint16_t port_id);

int dp_ports_init(void);
void dp_ports_free(void);

struct dp_port *dp_get_pf0(void);
struct dp_port *dp_get_pf1(void);
struct dp_port *dp_get_pf(uint16_t index);

int dp_port_start(struct dp_port *port);
int dp_port_stop(struct dp_port *port);

#define DP_FOREACH_PORT(DP_PORTS, VARNAME) \
	for (struct dp_port *VARNAME = (DP_PORTS)->ports; \
		 VARNAME < (DP_PORTS)->end; \
		 ++VARNAME)

#ifdef __cplusplus
}
#endif

#endif
