#include "dp_lpm.h"
#include "dp_flow.h"
#include "dp_util.h"
#include "node_api.h"
#include "dp_mbuf_dyn.h"
#include <rte_errno.h>

static struct vm_entry vm_table[DP_MAX_PORTS];
static struct rte_hash *vm_handle_tbl = NULL;

static uint32_t dp_router_gw_ip4 = RTE_IPV4(169, 254, 0, 1);
static uint8_t dp_router_gw_ip6[16] = {0xfe,0x80, 0,0,0,0,0,0,0,0,0,0,0,0,0,0x01};

void dp_init_vm_handle_tbl(int socket_id)
{
	struct rte_hash_parameters handle_table_params = {
		.name = NULL,
		.entries = DP_MAX_PORTS,
		.key_len =  VM_MACHINE_ID_STR_LEN,
		.hash_func = rte_jhash,
		.hash_func_init_val = 0xfee1900d,
		.extra_flag = 0,
	};
	char s[64];

	snprintf(s, sizeof(s), "vm_handle_table_%u", socket_id);
	handle_table_params.name = s;
	handle_table_params.socket_id = socket_id;
	vm_handle_tbl = rte_hash_create(&handle_table_params);
	if(!vm_handle_tbl)
		rte_exit(EXIT_FAILURE, "create vm handle table failed\n");
}

void dp_map_vm_handle(void *key, uint16_t portid)
{
	uint16_t *p_port_id = rte_zmalloc("vm_handle_mapping", sizeof(uint16_t), RTE_CACHE_LINE_SIZE);

	if (!p_port_id)
		rte_exit(EXIT_FAILURE, "vm handle for port %d malloc data failed\n", portid);

	RTE_VERIFY(portid < DP_MAX_PORTS);
	rte_memcpy(vm_table[portid].machineid, key, sizeof(vm_table[portid].machineid));
	*p_port_id = portid;
	if (rte_hash_add_key_data(vm_handle_tbl, key, p_port_id) < 0)
		rte_exit(EXIT_FAILURE, "vm handle for port %d add data failed\n", portid);
}

int dp_get_portid_with_vm_handle(void *key)
{
	uint16_t *p_port_id;
	uint16_t ret_val;

	if (rte_hash_lookup_data(vm_handle_tbl, key, (void **)&p_port_id) < 0)
		return -1;
	ret_val = *p_port_id;

	return ret_val;
}

void dp_del_portid_with_vm_handle(void *key)
{
	uint16_t *p_port_id;

	if (rte_hash_lookup_data(vm_handle_tbl, key, (void **)&p_port_id) < 0)
		return;

	rte_free(p_port_id);
}

uint32_t dp_get_gw_ip4()
{
	return dp_router_gw_ip4;
}

uint8_t* dp_get_gw_ip6()
{
	return dp_router_gw_ip6;
}

int dp_get_active_vm_ports(int* act_ports)
{
	int i, count = 0;

	for (i = 0; i < DP_MAX_PORTS; i++)
		if (vm_table[i].vm_ready)
			act_ports[count++] = i;
	return count;
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

uint8_t* dp_get_vm_machineid(uint16_t portid)
{
	RTE_VERIFY(portid < DP_MAX_PORTS);
	return vm_table[portid].machineid;
}

int dp_get_vm_vni(uint16_t portid)
{
	RTE_VERIFY(portid < DP_MAX_PORTS);
	return vm_table[portid].vni;
}

uint8_t* dp_get_vm_ip6(uint16_t portid)
{
	RTE_VERIFY(portid < DP_MAX_PORTS);
	return vm_table[portid].info.vm_ipv6;
}

bool dp_is_vm_natted(uint16_t portid)
{
	RTE_VERIFY(portid < DP_MAX_PORTS);
	return (vm_table[portid].info.nat != DP_NAT_OFF);
}

uint32_t dp_get_vm_nat_ip(uint16_t portid)
{
	RTE_VERIFY(portid < DP_MAX_PORTS);
	return htonl(vm_table[portid].info.virt_ip);
}

uint16_t dp_get_vm_port_id_per_nat_ip(uint32_t nat_ip)
{
	int i;

	for (i = 0; i < DP_MAX_PORTS; i++)
		if (vm_table[i].vm_ready && (vm_table[i].info.virt_ip == nat_ip))
			return i;
	return -1;
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

static bool dp_is_more_vm_in_vni_avail(int portid)
{
	int i;

	for (i = 0; i < DP_MAX_PORTS; i++)
		if ((i != portid) && vm_table[i].vm_ready && 
			(vm_table[i].vni == vm_table[portid].vni))
			return true;
	return false;
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

int dp_del_route(uint16_t portid, uint32_t vni, uint32_t t_vni, 
				 uint32_t ip, uint8_t* ip6, uint8_t depth, int socketid)
{
	struct rte_rib_node *node;
	struct rte_rib *root;

	RTE_VERIFY(socketid < DP_NB_SOCKETS);
	RTE_VERIFY(portid < DP_MAX_PORTS);

	root = get_lpm(vni, socketid);
	if (!root)
		return EXIT_FAILURE;

	node = rte_rib_lookup_exact(root, ip, depth);
	if (node)
		rte_rib_remove(root, ip, depth);
	else
		return EXIT_FAILURE;

	return EXIT_SUCCESS;
}

int dp_add_route6(uint16_t portid, uint32_t vni, uint32_t t_vni, uint8_t* ipv6,
				 uint8_t* ext_ip6, uint8_t depth, int socketid)
{
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

int dp_del_route6(uint16_t portid, uint32_t vni, uint32_t t_vni, uint8_t* ipv6,
				 uint8_t* ext_ip6, uint8_t depth, int socketid)
{
	struct rte_rib6_node *node;
	struct rte_rib6 *root;

	RTE_VERIFY(socketid < DP_NB_SOCKETS);
	RTE_VERIFY(portid < DP_MAX_PORTS);

	root = get_lpm6(vni, socketid);
	if (!root)
		return EXIT_FAILURE;

	node = rte_rib6_lookup_exact(root, ipv6, depth);
	if (node)
		rte_rib6_remove(root, ipv6, depth);
	else
		return EXIT_FAILURE;

	return EXIT_SUCCESS;
}

void dp_set_vm_nat_ip(uint16_t portid, uint32_t ip)
{
	RTE_VERIFY(portid < DP_MAX_PORTS);
	vm_table[portid].info.virt_ip = ip;
	vm_table[portid].info.nat = DP_NAT_ON;
}

void dp_del_vm_nat_ip(uint16_t portid)
{
	RTE_VERIFY(portid < DP_MAX_PORTS);
	vm_table[portid].info.nat = DP_NAT_OFF;
	vm_table[portid].info.virt_ip = 0;
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

void setup_lpm(int port_id, int vni, const int socketid)
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
	vm_table[port_id].vm_ready = 1;
}

void setup_lpm6(int port_id, int vni, const int socketid)
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

void dp_del_vm(int portid, int socketid)
{
	RTE_VERIFY(socketid < DP_NB_SOCKETS);
	RTE_VERIFY(portid < DP_MAX_PORTS);

	if(dp_is_more_vm_in_vni_avail(portid)) {
		dp_del_route(portid, vm_table[portid].vni, 0,
					 vm_table[portid].info.own_ip, NULL, 32, socketid);
		dp_del_route6(portid, vm_table[portid].vni, 0,
				vm_table[portid].info.dhcp_ipv6, NULL, 128, socketid);
		memset(&vm_table[portid], 0, sizeof(vm_table[portid]));
	} else {
		vm_table[portid].vm_ready = 0;
		if (vm_table[portid].ipv6_rib)
			rte_rib6_free(vm_table[portid].ipv6_rib[socketid]);
		if (vm_table[portid].ipv4_rib)
			rte_rib_free(vm_table[portid].ipv4_rib[socketid]);
		memset(&vm_table[portid], 0, sizeof(vm_table[portid]));
		dp_set_mac(portid);
	}
}
