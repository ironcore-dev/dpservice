#include "dp_lpm.h"
#include "dp_util.h"
#include "node_api.h"
#include <rte_errno.h>

static struct vm_entry vm_table[DP_MAX_PORTS];

static uint32_t dp_router_gw_ip4 = RTE_IPV4(169, 254, 0, 1);
static uint8_t dp_router_gw_ip6[16] = {0xfe,0x80, 0,0,0,0,0,0,0,0,0,0,0,0,0,0x01};

static void init_lcore_flowtable(uint16_t portid)
{
	int socket_id;

	struct rte_hash_parameters ipv4_table_params = {
		.name = NULL,
		.entries = FLOW_MAX / DP_ACTIVE_VF_PORT,
		.key_len =  sizeof(struct flow_key),
		.hash_func = rte_jhash,
		.hash_func_init_val = 0xfee1900d,
		.extra_flag = 0,
	};
	char s[64];

	RTE_VERIFY(portid < DP_MAX_PORTS);

	socket_id = rte_eth_dev_socket_id(portid);
	snprintf(s, sizeof(s), "ipv4_flow_table_%u", portid);
	ipv4_table_params.name = s;
	ipv4_table_params.socket_id = socket_id;
	vm_table[portid].ipv4_flow_tbl = rte_hash_create(&ipv4_table_params);
	if(!vm_table[portid].ipv4_flow_tbl)
		rte_exit(EXIT_FAILURE, "create ipv4 flow table failed\n");
}

void dp_build_flow_key(struct flow_key *key /* out */, const struct dp_flow *df_ptr /* in */)
{
	struct rte_tcp_hdr *tcp;
	struct rte_udp_hdr *udp;

	key->ip_dst = rte_be_to_cpu_32(df_ptr->dst.dst_addr);
	key->ip_src = rte_be_to_cpu_32(df_ptr->src.src_addr);
	key->proto = df_ptr->l4_type;

	switch (ipv4_hdr->next_proto_id) {
		case IPPROTO_TCP:
				tcp = (struct rte_tcp_hdr *)((unsigned char *)ipv4_hdr +
										sizeof(struct rte_ipv4_hdr));
				key->port_dst = rte_be_to_cpu_16(tcp->dst_port);
				key->port_src = rte_be_to_cpu_16(tcp->src_port);
				break;

		case IPPROTO_UDP:
				udp = (struct rte_udp_hdr *)((unsigned char *)ipv4_hdr +
										sizeof(struct rte_ipv4_hdr));
				key->port_dst = rte_be_to_cpu_16(udp->dst_port);
				key->port_src = rte_be_to_cpu_16(udp->src_port);
				break;

		default:
				key->port_dst = 0;
				key->port_src = 0;
				break;
	}

	if (key->ip_src > key->ip_dst) {
		uint32_t ip_tmp;
		uint16_t port_tmp;
		ip_tmp = key->ip_src;
		key->ip_src = key->ip_dst;
		key->ip_dst = ip_tmp;
		port_tmp = key->port_src;
		key->port_src = key->port_dst;
		key->port_dst = port_tmp;
	}
}

bool dp_flow_exists(uint16_t portid, struct flow_key *key)
{
	int ret;

	RTE_VERIFY(portid < DP_MAX_PORTS);
	ret = rte_hash_lookup(vm_table[portid].ipv4_flow_tbl, key);
	if (ret < 0)
		return false;
	return true;
}

void dp_add_flow(uint16_t portid, struct flow_key *key)
{
	RTE_VERIFY(portid < DP_MAX_PORTS);
	if (rte_hash_add_key(vm_table[portid].ipv4_flow_tbl, key) < 0)
		rte_exit(EXIT_FAILURE, "flow table for port %d add key failed\n", portid);
}

void dp_add_flow_data(uint16_t portid, struct flow_key *key, void* data)
{
	RTE_VERIFY(portid < DP_MAX_PORTS);
	if (rte_hash_add_key_data(vm_table[portid].ipv4_flow_tbl, key, data) < 0)
		rte_exit(EXIT_FAILURE, "flow table for port %d add data failed\n", portid);
}

void dp_get_flow_data(uint16_t portid, struct flow_key *key, void **data)
{
	RTE_VERIFY(portid < DP_MAX_PORTS);
	if (rte_hash_lookup_data(vm_table[portid].ipv4_flow_tbl, key, data) < 0)
		rte_exit(EXIT_FAILURE, "flow table for port %d add data failed\n", portid);
}

uint32_t dp_get_gw_ip4()
{
	return dp_router_gw_ip4;
}

uint8_t* dp_get_gw_ip6()
{
	return dp_router_gw_ip6;
}

uint32_t dp_get_dhcp_range_ip4(uint16_t portid)
{
	RTE_VERIFY(portid < DP_MAX_PORTS);
	return vm_table[portid].info.own_ip;
}


uint8_t* dp_get_dhcp_range_ip6(uint16_t portid)
{
	RTE_VERIFY(portid < DP_MAX_PORTS);
	return vm_table[portid].info.dhcp_ipv6;
}

uint8_t* dp_get_vm_ip6(uint16_t portid)
{
	RTE_VERIFY(portid < DP_MAX_PORTS);
	return vm_table[portid].info.vm_ipv6;
}

static struct rte_rib* get_lpm(int vni, const int socketid)
{
	int i;

	for (i = 0; i < DP_MAX_PORTS; i++)
		if (vm_table[i].vm_ready && (vm_table[i].vni == vni))
			return vm_table[i].ipv4_rib[socketid];

	return NULL;
}

static struct rte_rib6* get_lpm6(int vni, const int socketid)
{
	int i;

	for (i = 0; i < DP_MAX_PORTS; i++)
		if (vm_table[i].vm_ready && (vm_table[i].vni == vni))
			return vm_table[i].ipv6_rib[socketid];

	return NULL;
}

int dp_add_route(uint16_t portid, uint32_t vni, uint32_t t_vni, 
				 uint32_t ip, uint8_t* ip6, uint8_t depth, int socketid)
{
	struct vm_route *route = NULL;
	struct rte_rib_node *node;
	struct rte_rib *root;
	int ret = 0;

	RTE_VERIFY(socketid < DP_NB_SOCKETS);
	RTE_VERIFY(portid < DP_MAX_PORTS);

	root = get_lpm(vni, socketid);
	if (!root)
		return -1;

	node = rte_rib_insert(root, ip, depth);
	if (node) {
		ret = rte_rib_set_nh(node, portid);
		if (ret < 0) {
			rte_exit(EXIT_FAILURE,
				"Unable to add entry %u to the DP RIB table on socket %d\n",
				portid, socketid);
		}
		/* This is an external route */
		if (dp_is_pf_port_id(portid)) {
			route = rte_rib_get_ext(node);
			route->vni = t_vni;
			rte_memcpy(route->nh_ipv6, ip6, sizeof(route->nh_ipv6));
		}
	} else {
		rte_exit(EXIT_FAILURE,
			"Unable to add entry %u to the DP RIB table on socket %d\n",
			portid, socketid);
	}
	return ret;
}

int dp_add_route6(uint16_t portid, uint32_t vni, uint32_t t_vni, uint8_t* ipv6,
				 uint8_t* ext_ip6, uint8_t depth, int socketid) {

	struct vm_route *route = NULL;
	struct rte_rib6_node *node;
	struct rte_rib6 *root;
	int ret = 0;

	RTE_VERIFY(socketid < DP_NB_SOCKETS);
	RTE_VERIFY(portid < DP_MAX_PORTS);

	root = get_lpm6(vni, socketid);
	if (!root)
		return -1;

	node = rte_rib6_insert(root, ipv6, depth);
	if (node) {
		ret = rte_rib6_set_nh(node, portid);
		if (ret < 0) {
			rte_exit(EXIT_FAILURE,
				"Unable to add entry %u to the DP RIB table on socket %d\n",
				portid, socketid);
		}
		/* This is an external route */
		if (dp_is_pf_port_id(portid)) {
			route = rte_rib6_get_ext(node);
			route->vni = t_vni;
			rte_memcpy(route->nh_ipv6, ext_ip6, sizeof(route->nh_ipv6));
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
	vm_table[portid].info.own_ip = ip;
	vm_table[portid].info.depth = depth;
} 

void dp_set_dhcp_range_ip6(uint16_t portid, uint8_t* ipv6, uint8_t depth, int socketid)
{
	RTE_VERIFY(portid < DP_MAX_PORTS);
	RTE_VERIFY(socketid < DP_NB_SOCKETS);
	rte_memcpy(&vm_table[portid].info.dhcp_ipv6, ipv6, 16);
	vm_table[portid].info.depth = depth;
}

void dp_set_vm_ip6(uint16_t portid, uint8_t* ipv6)
{
	RTE_VERIFY(portid < DP_MAX_PORTS);
	rte_memcpy(&vm_table[portid].info.vm_ipv6, ipv6, 16);
}

void dp_set_mac(uint16_t portid)
{
	RTE_VERIFY(portid < DP_MAX_PORTS);
	rte_eth_macaddr_get(portid, &vm_table[portid].info.own_mac);
} 

struct rte_ether_addr *dp_get_mac(uint16_t portid)
{
	RTE_VERIFY(portid < DP_MAX_PORTS);
	return &vm_table[portid].info.own_mac;
}

void dp_set_neigh_mac(uint16_t portid, struct rte_ether_addr* neigh)
{
	RTE_VERIFY(portid < DP_MAX_PORTS);
	rte_ether_addr_copy(neigh,  &vm_table[portid].info.neigh_mac);
} 

struct rte_ether_addr *dp_get_neigh_mac(uint16_t portid)
{
	RTE_VERIFY(portid < DP_MAX_PORTS);
	return &vm_table[portid].info.neigh_mac;
} 

void setup_lpm(int port_id, int machine_id, int vni, const int socketid)
{
	struct rte_rib_conf config_ipv4;
	struct rte_rib* root;
	char s[64];

	RTE_VERIFY(socketid < DP_NB_SOCKETS);
	RTE_VERIFY(port_id < DP_MAX_PORTS);

	root = get_lpm(vni, socketid);

	if (!root) {
		/* create the LPM table */
		config_ipv4.max_nodes = IPV4_DP_RIB_MAX_RULES;
		config_ipv4.ext_sz = sizeof(struct vm_route);

		snprintf(s, sizeof(s), "IPV4_DP_RIB_%d_%d", vni, socketid);
		root = rte_rib_create(s, socketid, &config_ipv4);
		if (root == NULL)
			rte_exit(EXIT_FAILURE,
				"Unable to create the DP RIB table on socket %d\n",
				socketid);
	}
	vm_table[port_id].ipv4_rib[socketid] = root;
	vm_table[port_id].vni = vni;
	vm_table[port_id].machine_id = machine_id;
	init_lcore_flowtable(port_id);
	vm_table[port_id].vm_ready = 1;
}

void setup_lpm6(int port_id, int machine_id, int vni, const int socketid)
{
	struct rte_rib6_conf config_ipv6;
	struct rte_rib6* root;
	char s[64];

	RTE_VERIFY(socketid < DP_NB_SOCKETS);
	RTE_VERIFY(port_id < DP_MAX_PORTS);

	root = get_lpm6(vni, socketid);

	if (!root) {
		/* create the LPM table */
		config_ipv6.max_nodes = IPV6_DP_RIB_MAX_RULES;
		config_ipv6.ext_sz = sizeof(struct vm_route);

		snprintf(s, sizeof(s), "IPV6_DP_RIB_%d_%d", vni, socketid);
		root = rte_rib6_create(s, socketid, &config_ipv6);
		if (root == NULL) {
			
			rte_exit(EXIT_FAILURE,
				"Unable to create the DP RIB table on socket %d\n",
				socketid);
		}
	}
	vm_table[port_id].ipv6_rib[socketid] = root;
	vm_table[port_id].vni = vni;
	vm_table[port_id].machine_id = machine_id;  
	vm_table[port_id].vm_ready = 1;
}

int lpm_get_ip4_dst_port(int port_id, int t_vni, const struct rte_ipv4_hdr *ipv4_hdr, struct vm_route *r, int socketid)
{
	uint32_t dst_ip = rte_be_to_cpu_32(ipv4_hdr->dst_addr);
	struct rte_rib_node *node;
	struct rte_rib *root;
	uint64_t next_hop;

	if (t_vni)
		root = get_lpm(t_vni, socketid);
	else
		root = vm_table[port_id].ipv4_rib[socketid];

	if (!root)
		return DP_ROUTE_DROP;

	node = rte_rib_lookup(root, dst_ip);

	if (node) {
		if (rte_rib_get_nh(node, &next_hop) != 0)
			return DP_ROUTE_DROP;
		if (dp_is_pf_port_id(next_hop))
			*r = *(struct vm_route *)rte_rib_get_ext(node);
		return next_hop;
	}

	return DP_ROUTE_DROP;
}

int lpm_get_ip6_dst_port(int port_id, int t_vni, const struct rte_ipv6_hdr *ipv6_hdr, struct vm_route *r, int socketid)
{
	struct rte_rib6_node *node;
	struct rte_rib6 *root;
	uint64_t next_hop;

	if (t_vni)
		root = get_lpm6(t_vni, socketid);
	else
		root = vm_table[port_id].ipv6_rib[socketid];

	if (!root)
		return DP_ROUTE_DROP;

	node = rte_rib6_lookup(root, ipv6_hdr->dst_addr);

	if (node) {
		if (rte_rib6_get_nh(node, &next_hop) != 0)
			return DP_ROUTE_DROP;
		if (dp_is_pf_port_id(next_hop))
			*r = *(struct vm_route *)rte_rib6_get_ext(node);
		 return next_hop;
	}

	return DP_ROUTE_DROP;
}
