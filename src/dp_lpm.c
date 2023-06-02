#include <rte_errno.h>
#include "dp_log.h"
#include "dp_lpm.h"
#include "dp_flow.h"
#include "dp_error.h"
#include "dp_mbuf_dyn.h"
#include "dp_firewall.h"
#include "dp_vni.h"

static struct vm_entry vm_table[DP_MAX_PORTS];
static struct rte_hash *vm_handle_tbl = NULL;

static const uint32_t dp_router_gw_ip4 = RTE_IPV4(169, 254, 0, 1);
static const uint8_t dp_router_gw_ip6[16] = {0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01};

int dp_lpm_init(int socket_id)
{
	vm_handle_tbl = dp_create_jhash_table(DP_MAX_PORTS, VM_MACHINE_ID_STR_LEN,
										  "vm_handle_table", socket_id);
	if (!vm_handle_tbl)
		return DP_ERROR;

	return DP_OK;
}

void dp_lpm_free()
{
	dp_free_jhash_table(vm_handle_tbl);
}

int dp_lpm_reset_all_route_tables(int socketid)
{
	int i;

	if (DP_FAILED(dp_reset_vni_all_route_tables(socketid))) {
		DPS_LOG_ERR("resetting vni route table failed for socketid: %d", socketid);
		return DP_ERROR;
	}

	for (i = 0; i < DP_MAX_PORTS; i++)
		if (vm_table[i].vm_ready) {
			if (dp_add_route(i, vm_table[i].vni, 0, vm_table[i].info.own_ip, NULL, 32, rte_eth_dev_socket_id(i))) {
				DPS_LOG_ERR("dp_add_route failed during table reset");
				return DP_ERROR;
			}
			if (dp_add_route6(i, vm_table[i].vni, 0, vm_table[i].info.dhcp_ipv6, NULL, 128, rte_eth_dev_socket_id(i))) {
				DPS_LOG_ERR("dp_add_route6 failed during table reset");
				return DP_ERROR;
			}
		}
	return DP_OK;
}

int dp_map_vm_handle(void *key, uint16_t portid)
{
	uint16_t *p_port_id;

	p_port_id = rte_zmalloc("vm_handle_mapping", sizeof(uint16_t), RTE_CACHE_LINE_SIZE);
	if (!p_port_id) {
		DPS_LOG_ERR("vm handle for port %d malloc data failed", portid);
		return EXIT_FAILURE;
	}

	RTE_VERIFY(portid < DP_MAX_PORTS);
	if (rte_hash_lookup(vm_handle_tbl, key) >= 0)
		goto err;

	rte_memcpy(vm_table[portid].machineid, key, sizeof(vm_table[portid].machineid));
	*p_port_id = portid;
	if (rte_hash_add_key_data(vm_handle_tbl, key, p_port_id) < 0) {
		DPS_LOG_ERR("vm handle for port %d add data failed", portid);
		goto err;
	}
	return EXIT_SUCCESS;

err:
	rte_free(p_port_id);
	return EXIT_FAILURE;
}

// TODO(plague?): this needs DP_FAILED() handling, but also uint16_t retval
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
	uint16_t *p_port_id = NULL;

	rte_hash_lookup_data(vm_handle_tbl, key, (void **)&p_port_id);
	rte_free(p_port_id);
	rte_hash_del_key(vm_handle_tbl, key);
}

uint32_t dp_get_gw_ip4()
{
	return dp_router_gw_ip4;
}

const uint8_t *dp_get_gw_ip6()
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

int dp_get_vm_vni(uint16_t portid)
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

int dp_add_route(uint16_t portid, uint32_t vni, uint32_t t_vni,
				 uint32_t ip, uint8_t *ip6, uint8_t depth, int socketid)
{
	struct vm_route *route = NULL;
	struct rte_rib_node *node;
	struct rte_rib *root;
	int ret = EXIT_SUCCESS;

	RTE_VERIFY(socketid < DP_NB_SOCKETS);
	RTE_VERIFY(portid < DP_MAX_PORTS);

	root = dp_get_vni_route4_table(vni, socketid);
	if (!root) {
		ret = DP_GRPC_ERR_ADD_ROUTE_NO_VM;
		goto err;
	}

	node = rte_rib_lookup_exact(root, ip, depth);
	if (node) {
		ret = DP_GRPC_ERR_ADD_ROUTE_FAIL4;
		goto err;
	}

	node = rte_rib_insert(root, ip, depth);
	if (node) {
		ret = rte_rib_set_nh(node, portid);
		if (ret < 0) {
			ret = DP_GRPC_ERR_ADD_ROUTE_FAIL4;
			goto err;
		}
		/* This is an external route */
		if (dp_port_is_pf(portid)) {
			route = rte_rib_get_ext(node);
			route->vni = t_vni;
			rte_memcpy(route->nh_ipv6, ip6, sizeof(route->nh_ipv6));
		}
	} else {
		ret = DP_GRPC_ERR_ADD_ROUTE_FAIL4;
		goto err;
	}

	return ret;
err:
	// Addroute with 0.0.0.0 is used by metalnet as a periodic VNI-present query
	if (ip == 0 && ret == DP_GRPC_ERR_ADD_ROUTE_NO_VM)
		DPS_LOG_DEBUG("Unable to add entry %u to the DP RIB table on socket %d", portid, socketid);
	else
		DPS_LOG_WARNING("Unable to add entry %u to the DP RIB table on socket %d", portid, socketid);
	return ret;
}

int dp_del_route(uint16_t portid, uint32_t vni, uint32_t t_vni,
				 uint32_t ip, uint8_t *ip6, uint8_t depth, int socketid)
{
	struct rte_rib_node *node;
	struct rte_rib *root;
	uint64_t next_hop;

	RTE_VERIFY(socketid < DP_NB_SOCKETS);
	RTE_VERIFY(portid < DP_MAX_PORTS);

	root = dp_get_vni_route4_table(vni, socketid);
	if (!root)
		return EXIT_FAILURE;

	node = rte_rib_lookup_exact(root, ip, depth);
	if (node) {
		if (!DP_FAILED(rte_rib_get_nh(node, &next_hop))) {
			if (next_hop != portid)
				return EXIT_FAILURE;
		}
		rte_rib_remove(root, ip, depth);
	} else {
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

static void dp_copy_route_to_mbuf(struct rte_rib_node *node, dp_reply *rep, bool ext_routes, uint16_t per_buf)
{
	struct vm_route *route;
	dp_route *rp_route;
	uint32_t ipv4 = 0;
	uint8_t depth = 0;

	rp_route = &((&rep->route)[rep->com_head.msg_count % per_buf]);
	rep->com_head.msg_count++;

	rte_rib_get_ip(node, &ipv4);
	rte_rib_get_depth(node, &depth);
	rp_route->pfx_ip_type = RTE_ETHER_TYPE_IPV4;
	rp_route->pfx_ip.addr = ipv4;
	rp_route->pfx_length = depth;

	if (ext_routes) {
		route = (struct vm_route *)rte_rib_get_ext(node);
		rp_route->trgt_hop_ip_type = RTE_ETHER_TYPE_IPV6;
		rp_route->trgt_vni = route->vni;
		rte_memcpy(rp_route->trgt_ip.addr6, route->nh_ipv6,
					sizeof(rp_route->trgt_ip.addr6));
	}
}

void dp_list_routes(int vni, struct rte_mbuf *m, int socketid, uint16_t portid,
					struct rte_mbuf *rep_arr[], bool ext_routes)
{
	int8_t rep_arr_size = DP_MBUF_ARR_SIZE;
	struct rte_mbuf *m_new, *m_curr = m;
	struct rte_rib_node *node = NULL;
	struct rte_rib *root;
	uint16_t msg_per_buf;
	uint32_t ipv4 = 0;
	uint8_t depth = 0;
	uint64_t next_hop;
	dp_reply *rep;

	RTE_VERIFY(socketid < DP_NB_SOCKETS);

	root = dp_get_vni_route4_table(vni, socketid);
	if (!root)
		goto out;

	msg_per_buf = dp_first_mbuf_to_grpc_arr(m_curr, rep_arr,
										    &rep_arr_size, sizeof(dp_route));
	rep = rte_pktmbuf_mtod(m_curr, dp_reply*);

	do {
		node = rte_rib_get_nxt(root, RTE_IPV4(0, 0, 0, 0), 0, node, RTE_RIB_GET_NXT_ALL);
		if (node && (rte_rib_get_nh(node, &next_hop) == 0) &&
			dp_port_is_pf(next_hop) && ext_routes) {
			if (rep->com_head.msg_count &&
			    (rep->com_head.msg_count % msg_per_buf == 0)) {
				m_new = dp_add_mbuf_to_grpc_arr(m_curr, rep_arr, &rep_arr_size);
				if (!m_new)
					break;
				m_curr = m_new;
				rep = rte_pktmbuf_mtod(m_new, dp_reply*);
			}
			dp_copy_route_to_mbuf(node, rep, ext_routes, msg_per_buf);
		} else if (node && (rte_rib_get_nh(node, &next_hop) == 0) && !ext_routes) {
			if (rep->com_head.msg_count &&
			    (rep->com_head.msg_count % msg_per_buf == 0)) {
				m_new = dp_add_mbuf_to_grpc_arr(m_curr, rep_arr, &rep_arr_size);
				if (!m_new)
					break;
				m_curr = m_new;
				rep = rte_pktmbuf_mtod(m_new, dp_reply*);
			}
			if (next_hop == portid) {
				rte_rib_get_ip(node, &ipv4);
				rte_rib_get_depth(node, &depth);
				if ((dp_get_dhcp_range_ip4(portid) == ipv4) && (depth == DP_LPM_DHCP_IP_DEPTH))
					continue;
				dp_copy_route_to_mbuf(node, rep, ext_routes, msg_per_buf);
			}
		}
	} while (node != NULL);

	if (rep_arr_size < 0) {
		dp_last_mbuf_from_grpc_arr(m_curr, rep_arr);
		return;
	}

out:
	rep_arr[--rep_arr_size] = m_curr;
}

int dp_add_route6(uint16_t portid, uint32_t vni, uint32_t t_vni, uint8_t *ipv6,
				 uint8_t *ext_ip6, uint8_t depth, int socketid)
{
	struct vm_route *route = NULL;
	struct rte_rib6_node *node;
	struct rte_rib6 *root;
	int ret = EXIT_SUCCESS;

	RTE_VERIFY(socketid < DP_NB_SOCKETS);
	RTE_VERIFY(portid < DP_MAX_PORTS);

	root = dp_get_vni_route6_table(vni, socketid);
	if (!root)
		goto err;

	node = rte_rib6_lookup_exact(root, ipv6, depth);
	if (node)
		goto err;

	node = rte_rib6_insert(root, ipv6, depth);
	if (node) {
		ret = rte_rib6_set_nh(node, portid);
		if (ret < 0)
			goto err;

		/* This is an external route */
		if (dp_port_is_pf(portid)) {
			route = rte_rib6_get_ext(node);
			route->vni = t_vni;
			rte_memcpy(route->nh_ipv6, ext_ip6, sizeof(route->nh_ipv6));
		}
	} else {
		goto err;
	}
	return ret;
err:
	ret = EXIT_FAILURE;
	DPS_LOG_WARNING("Unable to add entry %u to the DP RIB6 table on socket %d", portid, socketid);
	return ret;
}

int dp_del_route6(uint16_t portid, uint32_t vni, uint32_t t_vni, uint8_t *ipv6,
				 uint8_t *ext_ip6, uint8_t depth, int socketid)
{
	struct rte_rib6_node *node;
	struct rte_rib6 *root;

	RTE_VERIFY(socketid < DP_NB_SOCKETS);
	RTE_VERIFY(portid < DP_MAX_PORTS);

	root = dp_get_vni_route6_table(vni, socketid);
	if (!root)
		return EXIT_FAILURE;

	node = rte_rib6_lookup_exact(root, ipv6, depth);
	if (node)
		rte_rib6_remove(root, ipv6, depth);
	else
		return EXIT_FAILURE;

	return EXIT_SUCCESS;
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

int setup_vm(int port_id, int vni, const int socketid)
{
	RTE_VERIFY(socketid < DP_NB_SOCKETS);
	RTE_VERIFY(port_id < DP_MAX_PORTS);

	if (DP_FAILED(dp_create_vni_route_table(vni, DP_IP_PROTO_IPV4, socketid)))
		return EXIT_FAILURE;

	dp_init_firewall_rules_list(port_id);
	vm_table[port_id].vni = vni;
	vm_table[port_id].vm_ready = 1;

	return EXIT_SUCCESS;
}

int setup_vm6(int port_id, int vni, const int socketid)
{
	RTE_VERIFY(socketid < DP_NB_SOCKETS);
	RTE_VERIFY(port_id < DP_MAX_PORTS);

	if (DP_FAILED(dp_create_vni_route_table(vni, DP_IP_PROTO_IPV6, socketid)))
		return EXIT_FAILURE;

	vm_table[port_id].vni = vni;
	vm_table[port_id].vm_ready = 1;
	return EXIT_SUCCESS;
}

int lpm_lookup_ip4_route(int port_id, int t_vni, const struct dp_flow *df, int socketid,
						 struct vm_route *r, uint32_t *route_key, uint64_t *dst_port_id)
{
	uint32_t dst_ip = rte_be_to_cpu_32(df->dst.dst_addr);
	struct rte_rib_node *node;
	struct rte_rib *root;
	uint64_t next_hop;
	int status;

	if (t_vni)
		root = dp_get_vni_route4_table(t_vni, socketid);
	else
		root = dp_get_vni_route4_table(vm_table[port_id].vni, socketid);

	if (!root)
		return DP_ROUTE_DROP;

	node = rte_rib_lookup(root, dst_ip);

	if (node) {
		if (rte_rib_get_nh(node, &next_hop) != 0)
			return DP_ROUTE_DROP;
		if (dp_port_is_pf(next_hop))
			*r = *(struct vm_route *)rte_rib_get_ext(node);

		*dst_port_id = next_hop;
		status = rte_rib_get_ip(node, route_key);
		if (status < 0)
			return DP_ROUTE_DROP;

		return 0;
	}

	return DP_ROUTE_DROP;
}

int lpm_get_ip6_dst_port(int port_id, int t_vni, const struct rte_ipv6_hdr *ipv6_hdr, struct vm_route *r, int socketid)
{
	struct rte_rib6_node *node;
	struct rte_rib6 *root;
	uint64_t next_hop;

	if (t_vni)
		root = dp_get_vni_route6_table(t_vni, socketid);
	else
		root = dp_get_vni_route6_table(vm_table[port_id].vni, socketid);

	if (!root)
		return DP_ROUTE_DROP;

	node = rte_rib6_lookup(root, ipv6_hdr->dst_addr);

	if (node) {
		if (rte_rib6_get_nh(node, &next_hop) != 0)
			return DP_ROUTE_DROP;
		if (dp_port_is_pf(next_hop))
			*r = *(struct vm_route *)rte_rib6_get_ext(node);
		 return next_hop;
	}

	return DP_ROUTE_DROP;
}

void dp_del_vm(int portid, int socketid, bool rollback)
{
	RTE_VERIFY(socketid < DP_NB_SOCKETS);
	RTE_VERIFY(portid < DP_MAX_PORTS);

	dp_del_route(portid, vm_table[portid].vni, 0,
				vm_table[portid].info.own_ip, NULL, 32, socketid);
	dp_del_route6(portid, vm_table[portid].vni, 0,
			vm_table[portid].info.dhcp_ipv6, NULL, 128, socketid);

	if (DP_FAILED(dp_delete_vni_route_table(vm_table[portid].vni, DP_IP_PROTO_IPV4)))
		DPS_LOG_WARNING("Unable to delete route table for vni %d type %d", vm_table[portid].vni, DP_IP_PROTO_IPV4);
	if (DP_FAILED(dp_delete_vni_route_table(vm_table[portid].vni, DP_IP_PROTO_IPV6)))
		DPS_LOG_WARNING("Unable to delete route table for vni %d type %d", vm_table[portid].vni, DP_IP_PROTO_IPV6);

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
