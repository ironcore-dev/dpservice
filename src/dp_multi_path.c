#include "dp_multi_path.h"
#include <math.h>

static egress_pf_port pf0_egress_select_table[port_select_table_size];

void fill_port_select_table(double frac)
{

	uint8_t round_frac = (uint8_t)round(frac * 10);

	for (uint8_t i = 0; i < round_frac; i++) {
		pf0_egress_select_table[i] = OWNER_PORT;
	}

	for (uint8_t i = round_frac; i < port_select_table_size; i++) {
		pf0_egress_select_table[i] = PEER_PORT;
	}
}

egress_pf_port calculate_port_by_hash(uint32_t hash)
{
	uint8_t modulo = hash % port_select_table_size;

	return pf0_egress_select_table[modulo];
}