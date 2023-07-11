#include "dp_lpm.h"
#include <rte_errno.h>
#include "dp_error.h"
#include "dp_firewall.h"
#include "dp_flow.h"
#include "dp_log.h"
#include "dp_mbuf_dyn.h"
#include "dp_vni.h"
#include "grpc/dp_grpc_responder.h"

static struct vm_entry vm_table[DP_MAX_PORTS];
static struct rte_hash *vm_handle_tbl = NULL;

static const uint32_t dp_router_gw_ip4 = RTE_IPV4(169, 254, 0, 1);
static const uint8_t dp_router_gw_ip6[16] = {0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01};

int dp_lpm_init(int socket_id)
{
	vm_handle_tbl = dp_create_jhash_table(DP_MAX_PORTS, VM_IFACE_ID_MAX_LEN,
										  "vm_handle_table", socket_id);
	if (!vm_handle_tbl)
		return DP_ERROR;

	return DP_OK;
}

void dp_lpm_free(void)
{
	dp_free_jhash_table(vm_handle_tbl);
}

static __rte_always_inline int dp_lpm_fill_route_tables(int portid, struct vm_entry *entry)
{
	int socket_id = rte_eth_dev_socket_id(portid);
	int ret;

	ret = dp_add_route(portid, entry->vni, 0, entry->info.own_ip, NULL, 32, socket_id);
	if (DP_FAILED(ret))
		return ret;

	ret = dp_add_route6(portid, entry->vni, 0, entry->info.dhcp_ipv6, NULL, 128, socket_id);
	if (DP_FAILED(ret))
		return ret;

	return DP_GRPC_OK;
}

int dp_lpm_reset_all_route_tables(int socketid)
{
	int ret;

	if (DP_FAILED(dp_reset_vni_all_route_tables(socketid)))
		return DP_GRPC_ERR_ROUTE_RESET;

	for (int i = 0; i < DP_MAX_PORTS; ++i) {
		if (vm_table[i].vm_ready) {
			ret = dp_lpm_fill_route_tables(i, &vm_table[i]);
			if (DP_FAILED(ret))
				return ret;
		}
	}

	return DP_GRPC_OK;
}

int dp_lpm_reset_route_tables(int vni, int socketid)
{
	int ret;

	if (DP_FAILED(dp_reset_vni_route_table(vni, DP_IP_PROTO_IPV4, socketid))) {
		DPS_LOG_ERR("Resetting vni route table failed", DP_LOG_VNI(vni), DP_LOG_SOCKID(socketid));
		return DP_GRPC_ERR_ROUTE_RESET;
	}

	if (DP_FAILED(dp_reset_vni_route_table(vni, DP_IP_PROTO_IPV6, socketid))) {
		DPS_LOG_ERR("Resetting vni route table failed", DP_LOG_VNI(vni), DP_LOG_SOCKID(socketid));
		return DP_GRPC_ERR_ROUTE_RESET;
	}

	for (int i = 0; i < DP_MAX_PORTS; ++i) {
		// TODO(plague?): the cast does not seem nice, define a type for VNIs?
		if (vm_table[i].vm_ready && (int)vm_table[i].vni == vni) {
			ret = dp_lpm_fill_route_tables(i, &vm_table[i]);
			if (DP_FAILED(ret))
				return ret;
		}
	}

	return DP_GRPC_OK;
}

int dp_map_vm_handle(void *key, uint16_t portid)
{
	uint16_t *p_port_id;
	int ret;

	p_port_id = rte_zmalloc("vm_handle_mapping", sizeof(uint16_t), RTE_CACHE_LINE_SIZE);
	if (!p_port_id) {
		DPS_LOG_ERR("Cannot allocate VM handle", DP_LOG_PORTID(portid));
		goto err;
	}

	RTE_VERIFY(portid < DP_MAX_PORTS);
	ret = rte_hash_lookup(vm_handle_tbl, key);
	if (ret != -ENOENT) {
		if (DP_FAILED(ret))
			DPS_LOG_ERR("VM handle lookup failed", DP_LOG_RET(ret));
		else
			DPS_LOG_ERR("VM handle already exists");
		goto err_free;
	}

	rte_memcpy(vm_table[portid].machineid, key, sizeof(vm_table[portid].machineid));
	*p_port_id = portid;
	ret = rte_hash_add_key_data(vm_handle_tbl, key, p_port_id);
	if (DP_FAILED(ret)) {
		DPS_LOG_ERR("Cannot add VM handle data", DP_LOG_PORTID(portid), DP_LOG_RET(ret));
		goto err_free;
	}
	return DP_OK;

err_free:
	rte_free(p_port_id);
err:
	return DP_ERROR;
}

int dp_get_portid_with_vm_handle(void *key)
{
	uint16_t *p_port_id;
	int ret;

	ret = rte_hash_lookup_data(vm_handle_tbl, key, (void **)&p_port_id);
	if (DP_FAILED(ret))
		return ret;

	return *p_port_id;
}

void dp_del_portid_with_vm_handle(void *key)
{
	uint16_t *p_port_id = NULL;

	rte_hash_lookup_data(vm_handle_tbl, key, (void **)&p_port_id);
	rte_free(p_port_id);
	rte_hash_del_key(vm_handle_tbl, key);
}

uint32_t dp_get_gw_ip4(void)
{
	return dp_router_gw_ip4;
}

const uint8_t *dp_get_gw_ip6(void)
{
	return dp_router_gw_ip6;
}

void dp_set_vm_pxe_str(uint16_t portid, char *p_str)
{
	RTE_VERIFY(portid < DP_MAX_PORTS);
	rte_memcpy(vm_table[portid].info.pxe_str, p_str,
			   sizeof(vm_table[portid].info.pxe_str));
}

char *dp_get_vm_pxe_str(uint16_t portid)
{
	RTE_VERIFY(portid < DP_MAX_PORTS);
	return (char *)vm_table[portid].info.pxe_str;
}

int dp_get_active_vm_ports(int *act_ports)
{
	int i, count = 0;

	for (i = 0; i < DP_MAX_PORTS; i++)
		if (vm_table[i].vm_ready)
			act_ports[count++] = i;
	return count;
}

bool dp_arp_cycle_needed(uint16_t portid)
{
	RTE_VERIFY(portid < DP_MAX_PORTS);
	return  (vm_table[portid].vm_ready &&
			(vm_table[portid].info.neigh_mac.addr_bytes[0] == 0) &&
			(vm_table[portid].info.neigh_mac.addr_bytes[1] == 0) &&
			(vm_table[portid].info.neigh_mac.addr_bytes[2] == 0) &&
			(vm_table[portid].info.neigh_mac.addr_bytes[3] == 0) &&
			(vm_table[portid].info.neigh_mac.addr_bytes[4] == 0) &&
			(vm_table[portid].info.neigh_mac.addr_bytes[5] == 0));
}

uint32_t dp_get_dhcp_range_ip4(uint16_t portid)
{
	RTE_VERIFY(portid < DP_MAX_PORTS);
	return vm_table[portid].info.own_ip;
}

uint8_t *dp_get_dhcp_range_ip6(uint16_t portid)
{
	RTE_VERIFY(portid < DP_MAX_PORTS);
	return vm_table[portid].info.dhcp_ipv6;
}

uint8_t *dp_get_vm_machineid(uint16_t portid)
{
	RTE_VERIFY(portid < DP_MAX_PORTS);
	return vm_table[portid].machineid;
}

uint32_t dp_get_vm_vni(uint16_t portid)
{
	RTE_VERIFY(portid < DP_MAX_PORTS);
	return vm_table[portid].vni;
}

uint8_t *dp_get_vm_ip6(uint16_t portid)
{
	RTE_VERIFY(portid < DP_MAX_PORTS);
	return vm_table[portid].info.vm_ipv6;
}

uint8_t *dp_get_vm_ul_ip6(uint16_t portid)
{
	RTE_VERIFY(portid < DP_MAX_PORTS);
	return vm_table[portid].ul_ipv6;
}

int dp_add_route(uint16_t portid, uint32_t vni, uint32_t t_vni, uint32_t ip,
				 uint8_t *ip6, uint8_t depth, int socketid)
{
	struct vm_route *route = NULL;
	struct rte_rib_node *node;
	struct rte_rib *root;

	RTE_VERIFY(socketid < DP_NB_SOCKETS);
	RTE_VERIFY(portid < DP_MAX_PORTS);

	root = dp_get_vni_route4_table(vni, socketid);
	if (!root)
		return DP_GRPC_ERR_NO_VNI;

	node = rte_rib_lookup_exact(root, ip, depth);
	if (node)
		return DP_GRPC_ERR_ROUTE_EXISTS;

	node = rte_rib_insert(root, ip, depth);
	if (!node)
		return DP_GRPC_ERR_ROUTE_INSERT;

	// can only fail if node is NULL
	rte_rib_set_nh(node, portid);
	/* This is an external route */
	if (dp_port_is_pf(portid)) {
		route = rte_rib_get_ext(node);
		route->vni = t_vni;
		rte_memcpy(route->nh_ipv6, ip6, sizeof(route->nh_ipv6));
	}

	return DP_GRPC_OK;
}

int dp_del_route(uint16_t portid, uint32_t vni, __rte_unused uint32_t t_vni, uint32_t ip,
				 __rte_unused uint8_t *ip6, uint8_t depth, int socketid)
{
	struct rte_rib_node *node;
	struct rte_rib *root;
	uint64_t next_hop;

	RTE_VERIFY(socketid < DP_NB_SOCKETS);
	RTE_VERIFY(portid < DP_MAX_PORTS);

	root = dp_get_vni_route4_table(vni, socketid);
	if (!root)
		return DP_GRPC_ERR_NO_VNI;

	node = rte_rib_lookup_exact(root, ip, depth);
	if (!node)
		return DP_GRPC_ERR_ROUTE_NOT_FOUND;

	// can only fail if node or next_hop is NULL
	rte_rib_get_nh(node, &next_hop);
	if (next_hop != portid)
		return DP_GRPC_ERR_ROUTE_BAD_PORT;

	rte_rib_remove(root, ip, depth);
	return DP_GRPC_OK;
}

static __rte_always_inline bool dp_route_in_dhcp_range(struct rte_rib_node *node, uint16_t portid)
{
	uint32_t ipv4 = 0;
	uint8_t depth = 0;

	rte_rib_get_ip(node, &ipv4);
	rte_rib_get_depth(node, &depth);
	return dp_get_dhcp_range_ip4(portid) == ipv4 && depth == DP_LPM_DHCP_IP_DEPTH;
}

static int dp_list_route_entry(struct rte_rib_node *node, uint16_t portid, bool ext_routes,
							   struct dp_grpc_responder *responder)
{
	struct dpgrpc_route *reply;
	uint64_t next_hop;
	struct vm_route *vm_route;
	uint32_t ipv4;
	uint8_t depth;

	// can only fail when any argument is NULL
	rte_rib_get_nh(node, &next_hop);

	if ((ext_routes && dp_port_is_pf(next_hop))
		|| (!ext_routes && next_hop == portid && !dp_route_in_dhcp_range(node, portid))
	) {
		reply = dp_grpc_add_reply(responder);
		if (!reply)
			return DP_ERROR;

		rte_rib_get_ip(node, &ipv4);
		rte_rib_get_depth(node, &depth);
		reply->pfx_ip_type = RTE_ETHER_TYPE_IPV4;
		reply->pfx_addr = ipv4;
		reply->pfx_length = depth;

		if (ext_routes) {
			vm_route = (struct vm_route *)rte_rib_get_ext(node);
			reply->trgt_ip_type = RTE_ETHER_TYPE_IPV6;
			reply->trgt_vni = vm_route->vni;
			rte_memcpy(reply->trgt_addr6, vm_route->nh_ipv6, sizeof(reply->trgt_addr6));
		}

	}
	return DP_OK;
}

int dp_list_routes(int vni, int socketid, uint16_t portid, bool ext_routes,
				   struct dp_grpc_responder *responder)
{
	struct rte_rib_node *node = NULL;
	struct rte_rib *root;

	// TODO(plague): look into this globally
	RTE_VERIFY(socketid < DP_NB_SOCKETS);

	root = dp_get_vni_route4_table(vni, socketid);
	if (!root)
		return DP_OK;

	dp_grpc_set_multireply(responder, sizeof(struct dpgrpc_route));

	node = rte_rib_lookup_exact(root, RTE_IPV4(0, 0, 0, 0), 0);
	if (node)
		if (DP_FAILED(dp_list_route_entry(node, portid, ext_routes, responder)))
			return DP_ERROR;

	node = NULL;  // needed to start rte_rib_get_nxt() traversal
	while ((node = rte_rib_get_nxt(root, RTE_IPV4(0, 0, 0, 0), 0, node, RTE_RIB_GET_NXT_ALL))) {
		if (DP_FAILED(dp_list_route_entry(node, portid, ext_routes, responder)))
			return DP_ERROR;
	}

	return DP_OK;
}

int dp_add_route6(uint16_t portid, uint32_t vni, uint32_t t_vni, uint8_t *ipv6,
				  uint8_t *ext_ip6, uint8_t depth, int socketid)
{
	struct vm_route *route = NULL;
	struct rte_rib6_node *node;
	struct rte_rib6 *root;

	RTE_VERIFY(socketid < DP_NB_SOCKETS);
	RTE_VERIFY(portid < DP_MAX_PORTS);

	root = dp_get_vni_route6_table(vni, socketid);
	if (!root)
		return DP_GRPC_ERR_NO_VNI;

	node = rte_rib6_lookup_exact(root, ipv6, depth);
	if (node)
		return DP_GRPC_ERR_ROUTE_EXISTS;

	node = rte_rib6_insert(root, ipv6, depth);
	if (!node)
		return DP_GRPC_ERR_ROUTE_INSERT;

	// can only fail if node is NULL
	rte_rib6_set_nh(node, portid);
	/* This is an external route */
	if (dp_port_is_pf(portid)) {
		route = rte_rib6_get_ext(node);
		route->vni = t_vni;
		rte_memcpy(route->nh_ipv6, ext_ip6, sizeof(route->nh_ipv6));
	}

	return DP_GRPC_OK;
}

int dp_del_route6(uint16_t portid, uint32_t vni, __rte_unused uint32_t t_vni, uint8_t *ipv6,
				  __rte_unused uint8_t *ext_ip6, uint8_t depth, int socketid)
{
	struct rte_rib6_node *node;
	struct rte_rib6 *root;

	RTE_VERIFY(socketid < DP_NB_SOCKETS);
	RTE_VERIFY(portid < DP_MAX_PORTS);

	root = dp_get_vni_route6_table(vni, socketid);
	if (!root)
		return DP_GRPC_ERR_NO_VNI;

	node = rte_rib6_lookup_exact(root, ipv6, depth);
	if (!node)
		return DP_GRPC_ERR_ROUTE_NOT_FOUND;

	rte_rib6_remove(root, ipv6, depth);
	return DP_GRPC_OK;
}

void dp_set_dhcp_range_ip4(uint16_t portid, uint32_t ip, uint8_t depth, int socketid)
{
	RTE_VERIFY(socketid < DP_NB_SOCKETS);
	RTE_VERIFY(portid < DP_MAX_PORTS);
	vm_table[portid].info.own_ip = ip;
	vm_table[portid].info.depth = depth;
}

void dp_set_vm_pxe_ip4(uint16_t portid, uint32_t ip, int socketid)
{
	RTE_VERIFY(socketid < DP_NB_SOCKETS);
	RTE_VERIFY(portid < DP_MAX_PORTS);
	vm_table[portid].info.pxe_ip = ip;
}

uint32_t dp_get_vm_pxe_ip4(uint16_t portid)
{
	RTE_VERIFY(portid < DP_MAX_PORTS);
	return vm_table[portid].info.pxe_ip;
}

void dp_set_dhcp_range_ip6(uint16_t portid, uint8_t *ipv6, uint8_t depth, int socketid)
{
	RTE_VERIFY(portid < DP_MAX_PORTS);
	RTE_VERIFY(socketid < DP_NB_SOCKETS);
	rte_memcpy(&vm_table[portid].info.dhcp_ipv6, ipv6, 16);
	vm_table[portid].info.depth = depth;
}

void dp_set_vm_ip6(uint16_t portid, uint8_t *ipv6)
{
	RTE_VERIFY(portid < DP_MAX_PORTS);
	rte_memcpy(&vm_table[portid].info.vm_ipv6, ipv6, 16);
}

void dp_set_vm_ul_ip6(uint16_t portid, uint8_t *ipv6)
{
	RTE_VERIFY(portid < DP_MAX_PORTS);
	rte_memcpy(&vm_table[portid].ul_ipv6, ipv6, 16);
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

void dp_set_neigh_mac(uint16_t portid, struct rte_ether_addr *neigh)
{
	RTE_VERIFY(portid < DP_MAX_PORTS);
	rte_ether_addr_copy(neigh,  &vm_table[portid].info.neigh_mac);
}

struct rte_ether_addr *dp_get_neigh_mac(uint16_t portid)
{
	RTE_VERIFY(portid < DP_MAX_PORTS);
	return &vm_table[portid].info.neigh_mac;
}

int dp_setup_vm(int port_id, int vni, const int socketid)
{
	RTE_VERIFY(socketid < DP_NB_SOCKETS);
	RTE_VERIFY(port_id < DP_MAX_PORTS);

	if (DP_FAILED(dp_create_vni_route_table(vni, DP_IP_PROTO_IPV4, socketid)))
		return DP_ERROR;

	dp_init_firewall_rules_list(port_id);
	vm_table[port_id].vni = vni;
	vm_table[port_id].vm_ready = 1;
	return DP_OK;
}

int dp_setup_vm6(int port_id, int vni, const int socketid)
{
	RTE_VERIFY(socketid < DP_NB_SOCKETS);
	RTE_VERIFY(port_id < DP_MAX_PORTS);

	if (DP_FAILED(dp_create_vni_route_table(vni, DP_IP_PROTO_IPV6, socketid)))
		return DP_ERROR;

	vm_table[port_id].vni = vni;
	vm_table[port_id].vm_ready = 1;
	return DP_OK;
}

int dp_lookup_ip4_route(int port_id, int t_vni, const struct dp_flow *df, int socketid,
						 struct vm_route *route, uint32_t *route_key, uint64_t *dst_port_id)
{
	uint32_t dst_ip = ntohl(df->dst.dst_addr);
	struct rte_rib_node *node;
	struct rte_rib *root;
	uint64_t next_hop;

	if (t_vni)
		root = dp_get_vni_route4_table(t_vni, socketid);
	else
		root = dp_get_vni_route4_table(vm_table[port_id].vni, socketid);

	if (!root)
		return DP_ERROR;

	node = rte_rib_lookup(root, dst_ip);
	if (!node)
		return DP_ERROR;

	if (DP_FAILED(rte_rib_get_nh(node, &next_hop)))
		return DP_ERROR;

	if (dp_port_is_pf(next_hop))
		*route = *(struct vm_route *)rte_rib_get_ext(node);

	*dst_port_id = next_hop;
	if (DP_FAILED(rte_rib_get_ip(node, route_key)))
		return DP_ERROR;

	return DP_OK;
}

int dp_get_ip6_dst_port(int port_id, int t_vni, const struct rte_ipv6_hdr *ipv6_hdr,
						 struct vm_route *route, int socketid)
{
	struct rte_rib6_node *node;
	struct rte_rib6 *root;
	uint64_t next_hop;

	if (t_vni)
		root = dp_get_vni_route6_table(t_vni, socketid);
	else
		root = dp_get_vni_route6_table(vm_table[port_id].vni, socketid);

	if (!root)
		return DP_ERROR;

	node = rte_rib6_lookup(root, ipv6_hdr->dst_addr);
	if (!node)
		return DP_ERROR;

	if (DP_FAILED(rte_rib6_get_nh(node, &next_hop)))
		return DP_ERROR;

	if (dp_port_is_pf(next_hop))
		*route = *(struct vm_route *)rte_rib6_get_ext(node);

	return next_hop;
}

void dp_del_vm(int portid, int socketid)
{
	RTE_VERIFY(socketid < DP_NB_SOCKETS);
	RTE_VERIFY(portid < DP_MAX_PORTS);

	dp_del_route(portid, vm_table[portid].vni, 0,
				vm_table[portid].info.own_ip, NULL, 32, socketid);
	dp_del_route6(portid, vm_table[portid].vni, 0,
			vm_table[portid].info.dhcp_ipv6, NULL, 128, socketid);

	if (DP_FAILED(dp_delete_vni_route_table(vm_table[portid].vni, DP_IP_PROTO_IPV4)))
		DPS_LOG_WARNING("Unable to delete route table", DP_LOG_VNI(vm_table[portid].vni), DP_LOG_PROTO(DP_IP_PROTO_IPV4));
	if (DP_FAILED(dp_delete_vni_route_table(vm_table[portid].vni, DP_IP_PROTO_IPV6)))
		DPS_LOG_WARNING("Unable to delete route table", DP_LOG_VNI(vm_table[portid].vni), DP_LOG_PROTO(DP_IP_PROTO_IPV6));

	dp_del_all_firewall_rules(portid);
	memset(&vm_table[portid], 0, sizeof(vm_table[portid]));
	// own mac address in the vm_entry needs to be refilled due to the above cleaning process
	dp_set_mac(portid);
}

struct dp_fwall_head *dp_get_fwall_head(int port_id)
{
	RTE_VERIFY(port_id < DP_MAX_PORTS);
	return &vm_table[port_id].fwall_head;
}

void dp_set_fwall_head(int port_id, struct dp_fwall_head *fwall_head)
{
	RTE_VERIFY(port_id < DP_MAX_PORTS);
	vm_table[port_id].fwall_head = *fwall_head;
}
