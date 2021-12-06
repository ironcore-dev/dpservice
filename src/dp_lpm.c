#include "dp_lpm.h"


static struct macip_entry mac_ip_table[DP_MAX_PORTS];
static struct rte_rib *ipv4_rib_lookup_struct[DP_NB_SOCKETS];

static uint32_t dp_router_gw_ip4 = RTE_IPV4(169, 254, 0, 1);
static uint8_t dp_router_gw_ip6[16] = {0xfe,0x80, 0,0,0,0,0,0,0,0,0,0,0,0,0,0x01};
/*TODO This should come from netlink */
static struct rte_ether_addr pf_neigh_mac = 
								{.addr_bytes[0] = 0x90,
								.addr_bytes[1] = 0x3c,
								.addr_bytes[2] = 0xb3,
								.addr_bytes[3] = 0x33,
								.addr_bytes[4] = 0x72,
								.addr_bytes[5] = 0xfb,
								};


uint32_t dp_get_gw_ip4() {
	return dp_router_gw_ip4;
}

uint8_t* dp_get_gw_ip6() {
	return dp_router_gw_ip6;
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
	struct rte_rib_node *node;
	int ret = 0;

	RTE_VERIFY(socketid < DP_NB_SOCKETS);
	RTE_VERIFY(portid < DP_MAX_PORTS);
	node = rte_rib_insert(ipv4_rib_lookup_struct[socketid], ip,
					  depth);
	if (node) {
		ret = rte_rib_set_nh(node, portid);
		if (ret < 0) {
			rte_exit(EXIT_FAILURE,
				"Unable to add entry %u to the DP RIB table on socket %d\n",
				portid, socketid);
	}
	} else {
		rte_exit(EXIT_FAILURE,
			"Unable to add entry %u to the DP RIB table on socket %d\n",
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
	struct rte_rib_conf config_ipv4;
	char s[64];

	RTE_VERIFY(socketid < DP_NB_SOCKETS);
	/* TODO this should be called by neighbour discovery */
	dp_set_neigh_mac (DP_PF_PORT, &pf_neigh_mac);
	/* create the LPM table */
	config_ipv4.max_nodes = IPV4_DP_RIB_MAX_RULES;
	config_ipv4.ext_sz = sizeof(uint64_t);

	snprintf(s, sizeof(s), "IPV4_DP_RIB_%d", socketid);
	ipv4_rib_lookup_struct[socketid] =
			rte_rib_create(s, socketid, &config_ipv4);
	if (ipv4_rib_lookup_struct[socketid] == NULL)
		rte_exit(EXIT_FAILURE,
			"Unable to create the DP RIB table on socket %d\n",
			socketid);
}

int lpm_get_ip4_dst_port(const struct rte_ipv4_hdr *ipv4_hdr, int socketid)
{
	uint32_t dst_ip = rte_be_to_cpu_32(ipv4_hdr->dst_addr);
	struct rte_rib_node *node;
	uint64_t next_hop;
	int ret;

	node = rte_rib_lookup(ipv4_rib_lookup_struct[socketid], dst_ip);

	if (node) {
		ret = rte_rib_get_nh(node, &next_hop);
		return next_hop;
	}	else
		return DP_PF_PORT;
}
