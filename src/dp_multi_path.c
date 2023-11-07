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

struct dp_port *dp_multipath_get_pf(uint32_t hash)
{
	if (!dp_conf_is_wcmp_enabled())
		return dp_get_pf0();

	enum egress_pf_port selected_port = pf0_egress_select_table[hash % PORT_SELECT_TABLE_SIZE];
	struct dp_port *owner_port = dp_get_pf0();
	struct dp_port *peer_port = dp_get_pf1();

	// basic logic of port redundancy if one of ports are down
	if ((selected_port == PEER_PORT && peer_port->link_status == RTE_ETH_LINK_UP)
		|| (selected_port == OWNER_PORT && owner_port->link_status == RTE_ETH_LINK_DOWN)
	) {
		return peer_port;
	}

	return owner_port;
}
