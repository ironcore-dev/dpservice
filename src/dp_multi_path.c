#include "dp_multi_path.h"

#include <math.h>
#include <rte_common.h>
#include <rte_ethdev.h>

#include "dp_conf.h"
#include "dp_port.h"

#define PORT_SELECT_TABLE_SIZE 10

enum egress_pf_port {
	OWNER_PORT,
	PEER_PORT,
};

static enum egress_pf_port pf0_egress_select_table[PORT_SELECT_TABLE_SIZE];

void dp_multipath_init(void)
{
	if (!dp_conf_is_wcmp_enabled())
		return;

	int frac = (int)lround(dp_conf_get_wcmp_perc() / (100.0/PORT_SELECT_TABLE_SIZE));

	for (int i = 0; i < frac; ++i)
		pf0_egress_select_table[i] = OWNER_PORT;

	for (int i = frac; i < PORT_SELECT_TABLE_SIZE; ++i)
		pf0_egress_select_table[i] = PEER_PORT;
}

uint16_t dp_multipath_get_pf(uint32_t hash)
{
	if (!dp_conf_is_wcmp_enabled())
		return dp_port_get_pf0_id();

	enum egress_pf_port selected_port = pf0_egress_select_table[hash % PORT_SELECT_TABLE_SIZE];
	uint16_t owner_port_id = dp_port_get_pf0_id();
	uint16_t peer_port_id = dp_port_get_pf1_id();

	// basic logic of port redundancy if one of ports are down
	if ((selected_port == PEER_PORT && dp_port_get_link_status(peer_port_id) == RTE_ETH_LINK_UP)
		|| (selected_port == OWNER_PORT && dp_port_get_link_status(owner_port_id) == RTE_ETH_LINK_DOWN)
	) {
		return peer_port_id;
	}

	return owner_port_id;
}
