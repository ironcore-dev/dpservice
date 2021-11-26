#include "dp_lpm.h"


static struct macip_entry mac_ip_table[DP_MAX_PORTS];
static struct rte_lpm *ipv4_l3fwd_lpm_lookup_struct[DP_NB_SOCKETS];

static uint32_t dp_router_gw_ip4 = RTE_IPV4(169, 254, 0, 1);
/*TODO This should come from netlink */
static struct rte_ether_addr pf_neigh_mac = 
								{.addr_bytes[0] = 0x90,
								.addr_bytes[1] = 0x3c,
								.addr_bytes[2] = 0xb3,
								.addr_bytes[3] = 0x33,
								.addr_bytes[4] = 0x72,
								.addr_bytes[5] = 0xfb,
								};

static uint8_t port_ip6s[DP_MAX_PORTS][16] = {
	{0xfe,0x80,0x00,0x00,0x00,0x00,0x00,0x00,0xb8,0x66,0xc7,0xff,0xfe,0xd5,0xce,0x25},
	{0xfe,0x80,0x00,0x00,0x00,0x00,0x00,0x00,0xb8,0x66,0xc7,0xff,0xfe,0xd5,0xce,0x25},
	{0xfe,0x80,0x00,0x00,0x00,0x00,0x00,0x00,0xb8,0x66,0xc7,0xff,0xfe,0xd5,0xce,0x25}
};

uint32_t dp_get_gw_ip4() {
	return dp_router_gw_ip4;
}

uint32_t dp_get_dhcp_range_ip4(uint16_t portid)
{
	RTE_VERIFY(portid < DP_MAX_PORTS);
	return mac_ip_table[portid].own_ip;
}


uint8_t* dp_get_ip6(uint16_t portid)
{
	RTE_VERIFY(portid < DP_MAX_PORTS);
	return mac_ip_table[portid].own_ipv6;
}

int dp_add_route(uint16_t portid, uint32_t ip, uint8_t depth, int socketid)
{
	int ret;

	RTE_VERIFY(socketid < DP_NB_SOCKETS);
	RTE_VERIFY(portid < DP_MAX_PORTS);
	ret = rte_lpm_add(ipv4_l3fwd_lpm_lookup_struct[socketid], ip,
					  depth, portid);

	if (ret < 0) {
		rte_exit(EXIT_FAILURE,
			"Unable to add entry %u to the l3fwd LPM table on socket %d\n",
			portid, socketid);
	}
	return ret;
}

void dp_set_dhcp_range_ip4(uint16_t portid, uint32_t ip, uint8_t depth, int socketid)
{
	RTE_VERIFY(socketid < DP_NB_SOCKETS);
	RTE_VERIFY(portid < DP_MAX_PORTS);
	mac_ip_table[portid].own_ip = ip;
	mac_ip_table[portid].depth = depth;
} 

void dp_set_ip6(uint16_t portid, uint8_t* ipv6, uint8_t depth, int socketid)
{
	RTE_VERIFY(portid < DP_MAX_PORTS);
	RTE_VERIFY(socketid < DP_NB_SOCKETS);
	rte_memcpy(&mac_ip_table[portid].own_ipv6, ipv6, 16);
	mac_ip_table[portid].depth = depth;
}

void dp_set_neigh_ip6(uint16_t portid, uint8_t* ipv6)
{
	RTE_VERIFY(portid < DP_MAX_PORTS);
	rte_memcpy(&mac_ip_table[portid].neigh_ipv6, ipv6, 16);
}

void dp_set_mac(uint16_t portid)
{
	RTE_VERIFY(portid < DP_MAX_PORTS);
	rte_eth_macaddr_get(portid, &mac_ip_table[portid].own_mac);
} 

struct rte_ether_addr *dp_get_mac(uint16_t portid)
{
	RTE_VERIFY(portid < DP_MAX_PORTS);
	return &mac_ip_table[portid].own_mac;
}

void dp_set_neigh_mac(uint16_t portid, struct rte_ether_addr* neigh)
{
	RTE_VERIFY(portid < DP_MAX_PORTS);
	rte_ether_addr_copy(neigh,  &mac_ip_table[portid].neigh_mac);
} 

struct rte_ether_addr *dp_get_neigh_mac(uint16_t portid)
{
	RTE_VERIFY(portid < DP_MAX_PORTS);
	return &mac_ip_table[portid].neigh_mac;
} 

void setup_lpm(const int socketid)
{
	struct rte_lpm_config config_ipv4;
	char s[64];

	RTE_VERIFY(socketid < DP_NB_SOCKETS);
	/* TODO this should be called by neighbour discovery */
	dp_set_neigh_mac (DP_PF_PORT, &pf_neigh_mac);
	/* create the LPM table */
	config_ipv4.max_rules = IPV4_L3FWD_LPM_MAX_RULES;
	config_ipv4.number_tbl8s = IPV4_L3FWD_LPM_NUMBER_TBL8S;
	config_ipv4.flags = 0;
	snprintf(s, sizeof(s), "IPV4_DP_LPM_%d", socketid);
	ipv4_l3fwd_lpm_lookup_struct[socketid] =
			rte_lpm_create(s, socketid, &config_ipv4);
	if (ipv4_l3fwd_lpm_lookup_struct[socketid] == NULL)
		rte_exit(EXIT_FAILURE,
			"Unable to create the l3fwd LPM table on socket %d\n",
			socketid);
}

int lpm_get_ip4_dst_port(const struct rte_ipv4_hdr *ipv4_hdr, int socketid)
{
	uint32_t dst_ip = rte_be_to_cpu_32(ipv4_hdr->dst_addr);
	uint32_t next_hop;

	if (rte_lpm_lookup(ipv4_l3fwd_lpm_lookup_struct[socketid], dst_ip, &next_hop) == 0)
		return next_hop;
	else
		return DP_PF_PORT;
}
