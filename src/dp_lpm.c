#include "dp_lpm.h"
#include <rte_errno.h>
#include "dp_conf.h"
#include "dp_error.h"
#include "dp_firewall.h"
#include "dp_flow.h"
#include "dp_log.h"
#include "dp_mbuf_dyn.h"
#include "dp_port.h"
#include "dp_vni.h"
#include "grpc/dp_grpc_responder.h"

static struct rte_hash *vm_handle_tbl = NULL;

static const uint32_t dp_router_gw_ip4 = RTE_IPV4(169, 254, 0, 1);
static const uint8_t dp_router_gw_ip6[16] = {0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01};

static const uint8_t *service_ul_ip;

int dp_lpm_init(int socket_id)
{
	vm_handle_tbl = dp_create_jhash_table(DP_MAX_PORTS, VM_IFACE_ID_MAX_LEN,
										  "vm_handle_table", socket_id);
	if (!vm_handle_tbl)
		return DP_ERROR;

	service_ul_ip = dp_conf_get_underlay_ip();

	return DP_OK;
}

void dp_lpm_free(void)
{
	dp_free_jhash_table(vm_handle_tbl);
}

static __rte_always_inline int dp_lpm_fill_route_tables(struct dp_port *port)
{
	int ret;

	ret = dp_add_route(port, port->vm.vni, 0, port->vm.info.own_ip, NULL, 32);
	if (DP_FAILED(ret))
		return ret;

	ret = dp_add_route6(port, port->vm.vni, 0, port->vm.info.dhcp_ipv6, NULL, 128);
	if (DP_FAILED(ret))
		return ret;

	return DP_GRPC_OK;
}

int dp_lpm_reset_all_route_tables(int socket_id)
{
	struct dp_ports *ports = dp_get_ports();
	int ret;

	if (DP_FAILED(dp_reset_all_vni_route_tables(socket_id)))
		return DP_GRPC_ERR_ROUTE_RESET;

	DP_FOREACH_PORT(ports, port) {
		if (!port->vm.ready)
			continue;
		ret = dp_lpm_fill_route_tables(port);
		if (DP_FAILED(ret))
			return ret;
	}

	return DP_GRPC_OK;
}

int dp_lpm_reset_route_tables(int vni, int socket_id)
{
	struct dp_ports *ports = dp_get_ports();
	int ret;

	if (DP_FAILED(dp_reset_vni_route_tables(vni, socket_id))) {
		DPS_LOG_ERR("Resetting vni route tables failed", DP_LOG_VNI(vni), DP_LOG_SOCKID(socket_id));
		return DP_GRPC_ERR_ROUTE_RESET;
	}

	DP_FOREACH_PORT(ports, port) {
		// TODO(plague?): the cast does not seem nice, define a type for VNIs?
		if (!port->vm.ready || (int)port->vm.vni != vni)
			continue;
		ret = dp_lpm_fill_route_tables(port);
		if (DP_FAILED(ret))
			return ret;
	}

	return DP_GRPC_OK;
}

int dp_map_vm_handle(const char key[VM_IFACE_ID_MAX_LEN], struct dp_port *port)
{
	hash_sig_t hash = rte_hash_hash(vm_handle_tbl, key);
	int ret;

	ret = rte_hash_lookup_with_hash(vm_handle_tbl, key, hash);
	if (ret != -ENOENT) {
		if (DP_FAILED(ret))
			DPS_LOG_ERR("VM handle lookup failed", DP_LOG_RET(ret));
		else
			DPS_LOG_ERR("VM handle already exists");
		return DP_ERROR;
	}

	ret = rte_hash_add_key_with_hash_data(vm_handle_tbl, key, hash, port);
	if (DP_FAILED(ret)) {
		DPS_LOG_ERR("Cannot add VM handle data", DP_LOG_PORTID(port->port_id), DP_LOG_RET(ret));
		return DP_ERROR;
	}

	static_assert(sizeof(port->vm.machineid) == VM_IFACE_ID_MAX_LEN, "Incompatible VM ID size");
	rte_memcpy(port->vm.machineid, key, VM_IFACE_ID_MAX_LEN);

	return DP_OK;
}

void dp_unmap_vm_handle(const void *key)
{
	rte_hash_del_key(vm_handle_tbl, key);
}

struct dp_port *dp_get_port_with_vm_handle(const void *key)
{
	struct dp_port *port;
	int ret;

	ret = rte_hash_lookup_data(vm_handle_tbl, key, (void **)&port);
	if (DP_FAILED(ret)) {
		if (ret != -ENOENT)
			DPS_LOG_ERR("Failed to look the VM port-id up", DP_LOG_RET(ret));
		return NULL;
	}

	return port;
}

uint32_t dp_get_gw_ip4(void)
{
	return dp_router_gw_ip4;
}

const uint8_t *dp_get_gw_ip6(void)
{
	return dp_router_gw_ip6;
}

bool dp_arp_cycle_needed(struct dp_port *port)
{
	return  (port->vm.ready &&
			(port->vm.info.neigh_mac.addr_bytes[0] == 0) &&
			(port->vm.info.neigh_mac.addr_bytes[1] == 0) &&
			(port->vm.info.neigh_mac.addr_bytes[2] == 0) &&
			(port->vm.info.neigh_mac.addr_bytes[3] == 0) &&
			(port->vm.info.neigh_mac.addr_bytes[4] == 0) &&
			(port->vm.info.neigh_mac.addr_bytes[5] == 0));
}

// TODO inline in dp_vm.c?
// TODO re-check the use of struct dp_port instead
const uint8_t *dp_get_port_ul_ip6(uint16_t port_id)
{
	struct dp_port *port = dp_get_port(port_id);

	return port && port->vm.ready ? port->vm.ul_ipv6 : service_ul_ip;
}

int dp_add_route(struct dp_port *port, uint32_t vni, uint32_t t_vni, uint32_t ip,
				 const uint8_t *ip6, uint8_t depth)
{
	struct vm_route *route = NULL;
	struct rte_rib_node *node;
	struct rte_rib *root;

	root = dp_get_vni_route4_table(vni);
	if (!root)
		return DP_GRPC_ERR_NO_VNI;

	node = rte_rib_lookup_exact(root, ip, depth);
	if (node)
		return DP_GRPC_ERR_ROUTE_EXISTS;

	node = rte_rib_insert(root, ip, depth);
	if (!node)
		return DP_GRPC_ERR_ROUTE_INSERT;

	// can only fail if node is NULL
	rte_rib_set_nh(node, port->port_id);
	/* This is an external route */
	if (port->port_type == DP_PORT_PF) {
		route = rte_rib_get_ext(node);
		route->vni = t_vni;
		rte_memcpy(route->nh_ipv6, ip6, sizeof(route->nh_ipv6));
	}

	return DP_GRPC_OK;
}

int dp_del_route(struct dp_port *port, uint32_t vni, uint32_t ip, uint8_t depth)
{
	struct rte_rib_node *node;
	struct rte_rib *root;
	uint64_t next_hop;

	root = dp_get_vni_route4_table(vni);
	if (!root)
		return DP_GRPC_ERR_NO_VNI;

	node = rte_rib_lookup_exact(root, ip, depth);
	if (!node)
		return DP_GRPC_ERR_ROUTE_NOT_FOUND;

	// can only fail if node or next_hop is NULL
	rte_rib_get_nh(node, &next_hop);
	if (next_hop != port->port_id)
		return DP_GRPC_ERR_ROUTE_BAD_PORT;

	rte_rib_remove(root, ip, depth);
	return DP_GRPC_OK;
}

static __rte_always_inline bool dp_route_in_dhcp_range(const struct rte_rib_node *node,
													   const struct dp_port *port)
{
	uint32_t ipv4 = 0;
	uint8_t depth = 0;

	// both calls only fail when either param is NULL
	rte_rib_get_ip(node, &ipv4);
	rte_rib_get_depth(node, &depth);
	return port->vm.info.own_ip == ipv4 && depth == DP_LPM_DHCP_IP_DEPTH;
}

static int dp_list_route_entry(struct rte_rib_node *node,
							   const struct dp_port *port,
							   bool ext_routes,
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
		|| (!ext_routes && next_hop == port->port_id && !dp_route_in_dhcp_range(node, port))
	) {
		reply = dp_grpc_add_reply(responder);
		if (!reply)
			return DP_GRPC_ERR_OUT_OF_MEMORY;

		rte_rib_get_ip(node, &ipv4);
		rte_rib_get_depth(node, &depth);
		reply->pfx_addr.ip_type = RTE_ETHER_TYPE_IPV4;
		reply->pfx_addr.ipv4 = ipv4;
		reply->pfx_length = depth;

		if (ext_routes) {
			vm_route = (struct vm_route *)rte_rib_get_ext(node);
			reply->trgt_addr.ip_type = RTE_ETHER_TYPE_IPV6;
			reply->trgt_vni = vm_route->vni;
			rte_memcpy(reply->trgt_addr.ipv6, vm_route->nh_ipv6, sizeof(reply->trgt_addr.ipv6));
		}

	}
	return DP_GRPC_OK;
}

int dp_list_routes(struct dp_port *port, int vni, bool ext_routes,
				   struct dp_grpc_responder *responder)
{
	struct rte_rib_node *node = NULL;
	struct rte_rib *root;
	int ret;

	root = dp_get_vni_route4_table(vni);
	if (!root)
		return DP_GRPC_ERR_NO_VNI;

	dp_grpc_set_multireply(responder, sizeof(struct dpgrpc_route));

	node = rte_rib_lookup_exact(root, RTE_IPV4(0, 0, 0, 0), 0);
	if (node) {
		ret = dp_list_route_entry(node, port, ext_routes, responder);
		if (DP_FAILED(ret))
			return ret;
	}

	node = NULL;  // needed to start rte_rib_get_nxt() traversal
	while ((node = rte_rib_get_nxt(root, RTE_IPV4(0, 0, 0, 0), 0, node, RTE_RIB_GET_NXT_ALL))) {
		ret = dp_list_route_entry(node, port, ext_routes, responder);
		if (DP_FAILED(ret))
			return ret;
	}

	return DP_GRPC_OK;
}

int dp_add_route6(struct dp_port *port, uint32_t vni, uint32_t t_vni, const uint8_t *ipv6,
				  const uint8_t *ext_ip6, uint8_t depth)
{
	struct vm_route *route = NULL;
	struct rte_rib6_node *node;
	struct rte_rib6 *root;

	root = dp_get_vni_route6_table(vni);
	if (!root)
		return DP_GRPC_ERR_NO_VNI;

	node = rte_rib6_lookup_exact(root, ipv6, depth);
	if (node)
		return DP_GRPC_ERR_ROUTE_EXISTS;

	node = rte_rib6_insert(root, ipv6, depth);
	if (!node)
		return DP_GRPC_ERR_ROUTE_INSERT;

	// can only fail if node is NULL
	rte_rib6_set_nh(node, port->port_id);
	/* This is an external route */
	if (port->port_type == DP_PORT_PF) {
		route = rte_rib6_get_ext(node);
		route->vni = t_vni;
		rte_memcpy(route->nh_ipv6, ext_ip6, sizeof(route->nh_ipv6));
	}

	return DP_GRPC_OK;
}

int dp_del_route6(struct dp_port *port, uint32_t vni, const uint8_t *ipv6, uint8_t depth)
{
	struct rte_rib6_node *node;
	struct rte_rib6 *root;
	uint64_t next_hop;

	root = dp_get_vni_route6_table(vni);
	if (!root)
		return DP_GRPC_ERR_NO_VNI;

	node = rte_rib6_lookup_exact(root, ipv6, depth);
	if (!node)
		return DP_GRPC_ERR_ROUTE_NOT_FOUND;

	// can only fail if node or next_hop is NULL
	rte_rib6_get_nh(node, &next_hop);
	if (next_hop != port->port_id)
		return DP_GRPC_ERR_ROUTE_BAD_PORT;

	rte_rib6_remove(root, ipv6, depth);
	return DP_GRPC_OK;
}

// TODO inline?
int dp_load_mac(struct dp_port *port)
{
	return rte_eth_macaddr_get(port->port_id, &port->vm.info.own_mac);
}

int dp_setup_vm(struct dp_port *port, int vni)
{
	if (DP_FAILED(dp_create_vni_route_tables(vni, port->socket_id)))
		return DP_ERROR;

	dp_init_firewall_rules(port);
	port->vm.vni = vni;
	port->vm.ready = 1;
	return DP_OK;
}

struct dp_port *dp_get_ip4_dst_port(const struct dp_port *port,
									int t_vni,
									const struct dp_flow *df,
									struct vm_route *route,
									uint32_t *route_key)
{
	uint32_t dst_ip = ntohl(df->dst.dst_addr);
	struct rte_rib_node *node;
	struct rte_rib *root;
	uint64_t next_hop;
	struct dp_port *dst_port;

	if (t_vni == 0)
		t_vni = port->vm.vni;

	root = dp_get_vni_route4_table(t_vni);
	if (!root)
		return NULL;

	node = rte_rib_lookup(root, dst_ip);
	if (!node)
		return NULL;

	if (DP_FAILED(rte_rib_get_nh(node, &next_hop)))
		return NULL;

	dst_port = dp_get_port(next_hop);
	if (!dst_port)
		return NULL;

	if (dst_port->port_type == DP_PORT_PF)
		*route = *(struct vm_route *)rte_rib_get_ext(node);

	if (DP_FAILED(rte_rib_get_ip(node, route_key)))
		return NULL;

	return dst_port;
}

struct dp_port *dp_get_ip6_dst_port(const struct dp_port *port,
									int t_vni,
									const struct rte_ipv6_hdr *ipv6_hdr,
									struct vm_route *route)
{
	struct rte_rib6_node *node;
	struct rte_rib6 *root;
	uint64_t next_hop;
	struct dp_port *dst_port;

	if (t_vni == 0)
		t_vni = port->vm.vni;

	root = dp_get_vni_route6_table(t_vni);
	if (!root)
		return NULL;

	node = rte_rib6_lookup(root, ipv6_hdr->dst_addr);
	if (!node)
		return NULL;

	if (DP_FAILED(rte_rib6_get_nh(node, &next_hop)))
		return NULL;

	dst_port = dp_get_port(next_hop);
	if (!dst_port)
		return NULL;

	if (dst_port->port_type == DP_PORT_PF)
		*route = *(struct vm_route *)rte_rib6_get_ext(node);

	return dst_port;
}

void dp_del_vm(struct dp_port *port)
{
	uint32_t vni = port->vm.vni;

	dp_del_route(port, vni, port->vm.info.own_ip, 32);
	dp_del_route6(port, vni, port->vm.info.dhcp_ipv6, 128);

	if (DP_FAILED(dp_delete_vni_route_tables(vni)))
		DPS_LOG_WARNING("Unable to delete route tables", DP_LOG_VNI(vni));

	dp_del_all_firewall_rules(port);

	memset(&port->vm, 0, sizeof(port->vm));
	// own mac address in the vm_entry needs to be refilled due to the above cleaning process
	dp_load_mac(port);
}

void dp_fill_ether_hdr(struct rte_ether_hdr *ether_hdr, uint16_t port_id, uint16_t ether_type)
{
	// TODO temporary fix
	struct dp_port *port = dp_get_port(port_id);

	rte_ether_addr_copy(&port->vm.info.neigh_mac, &ether_hdr->dst_addr);
	rte_ether_addr_copy(&port->vm.info.own_mac, &ether_hdr->src_addr);
	ether_hdr->ether_type = htons(ether_type);
}
