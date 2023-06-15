#include "dp_error.h"
#include "dp_lb.h"
#include <time.h>
#include "dp_lpm.h"
#include "dp_nat.h"
#ifdef ENABLE_VIRTSVC
#	include "dp_virtsvc.h"
#endif
#include "dp_vnf.h"
#include "dp_vni.h"
#include "dp_log.h"
#include "dpdk_layer.h"
#include "grpc/dp_grpc_impl.h"

#define DP_SHOW_EXT_ROUTES true
#define DP_SHOW_INT_ROUTES false

static uint32_t pfx_counter = 1;

void dp_last_mbuf_from_grpc_arr(struct rte_mbuf *m_curr, struct rte_mbuf *rep_arr[])
{
	dp_reply *rep;

	rte_pktmbuf_free(m_curr);
	rep = rte_pktmbuf_mtod(rep_arr[0], dp_reply*);
	rep->com_head.is_chained = 0;
}

uint16_t dp_first_mbuf_to_grpc_arr(struct rte_mbuf *m_curr, struct rte_mbuf *rep_arr[],
								   int8_t *idx, uint16_t size)
{
	uint16_t buf_size, msg_per_buf;
	dp_reply *rep;

	buf_size = m_curr->buf_len - m_curr->data_off - sizeof(dp_com_head);
	msg_per_buf = buf_size / size;
	rep = rte_pktmbuf_mtod(m_curr, dp_reply*);
	rep->com_head.msg_count = 0;

	return msg_per_buf;
}

static __rte_always_inline void dp_generate_underlay_ipv6(uint8_t *route)
{
	uint32_t local = htonl(pfx_counter);
	uint8_t random_byte;

	srand(time(NULL));
	random_byte = rand() % 256;

	/* First 8 bytes for host */
	rte_memcpy(route, get_underlay_conf()->src_ip6, DP_VNF_IPV6_ADDR_SIZE);
	/* Following 2 bytes for kernel routing and 1 byte reserved */
	memset(route + 8, 0, 3);

	#ifdef ENABLE_STATIC_UNDERLAY_IP
		/* 1 byte static value */
		uint8_t static_byte = 0x01;

		rte_memcpy(route + 11, &static_byte, 1);
		RTE_SET_USED(random_byte);
	#else
		/* 1 byte random value */
		rte_memcpy(route + 11, &random_byte, 1);
	#endif

	/* 4 byte counter */
	rte_memcpy(route + 12, &local, 4);

	pfx_counter++;
}

static int dp_insert_vnf_entry(struct dp_vnf_value *val, enum vnf_type v_type,
							   int vni, uint16_t portid, uint8_t *ul_addr6)
{
	dp_generate_underlay_ipv6(ul_addr6);
	val->v_type = v_type;
	val->portid = portid;
	val->vni = vni;
	return dp_set_vnf_value((void *)ul_addr6, val);
}

static __rte_always_inline int dp_remove_vnf_entry(struct dp_vnf_value *val, enum vnf_type v_type, uint16_t portid)
{
	val->v_type = v_type;
	val->portid = portid;
	val->vni = dp_get_vm_vni(portid);
	return dp_del_vnf_with_value(val);
}

struct rte_mbuf *dp_add_mbuf_to_grpc_arr(struct rte_mbuf *m_curr, struct rte_mbuf *rep_arr[], int8_t *size)
{
	dp_reply *rep, *rep_new;
	struct rte_mbuf *m_new;

	m_new = rte_pktmbuf_alloc(get_dpdk_layer()->rte_mempool);
	if (!m_new) {
		DPGRPC_LOG_WARNING("grpc rte_mbuf allocation failed");
		return NULL;
	}
	rep = rte_pktmbuf_mtod(m_curr, dp_reply*);
	rep->com_head.is_chained = 1;
	rep_new = rte_pktmbuf_mtod(m_new, dp_reply*);
	rep_new->com_head.msg_count = rep->com_head.msg_count;
	rep_new->com_head.is_chained = 0;
	if (--(*size) < 0)
		return NULL;
	rep_arr[*size] = m_curr;

	return m_new;
}

int dp_send_to_worker(dp_request *req)
{
	struct rte_mbuf *m = rte_pktmbuf_alloc(get_dpdk_layer()->rte_mempool);
	dp_request *head = rte_pktmbuf_mtod(m, dp_request *);
	int ret;

	*head = *req;

	ret = rte_ring_sp_enqueue(get_dpdk_layer()->grpc_tx_queue, m);
	if (DP_FAILED(ret)) {
		DPGRPC_LOG_WARNING("Cannot enqueue worker request", DP_LOG_RET(ret));
		return ret;
	}

	return DP_OK;
}

int dp_recv_from_worker(dp_reply *rep)
{
	struct rte_mbuf *m;
	dp_reply *head;
	int ret;

	ret = rte_ring_sc_dequeue(get_dpdk_layer()->grpc_rx_queue, (void **)&m);
	if (DP_FAILED(ret)) {
		if (ret != -ENOENT)
			DPGRPC_LOG_WARNING("Cannot dequeue worker response", DP_LOG_RET(ret));
		return ret;
	}

	head = rte_pktmbuf_mtod(m, dp_reply*);
	*rep = *head;
	rte_pktmbuf_free(m);
	return DP_OK;
}

int dp_recv_from_worker_with_mbuf(struct rte_mbuf **mbuf)
{
	struct rte_mbuf *m;
	int ret;

	ret = rte_ring_sc_dequeue(get_dpdk_layer()->grpc_rx_queue, (void **)&m);
	if (DP_FAILED(ret)) {
		if (ret != -ENOENT)
			DPGRPC_LOG_WARNING("Cannot dequeue worker response", DP_LOG_RET(ret));
		return ret;
	}

	*mbuf = m;
	return DP_OK;
}

__rte_always_inline void dp_fill_head(dp_com_head *head, uint16_t type,
									  uint8_t is_chained, uint8_t count)
{
	RTE_SET_USED(count);
	head->com_type = type;
	head->is_chained = is_chained;
	head->msg_count = 0;
	head->err_code = DP_GRPC_OK;
}

static int dp_process_add_lb(dp_request *req, dp_reply *rep)
{
	uint8_t ul_addr6[DP_VNF_IPV6_ADDR_SIZE];
	struct dp_vnf_value vnf_val = {0};
	int ret = DP_GRPC_OK;
	int vni;

	if (req->add_lb.ip_type == RTE_ETHER_TYPE_IPV4) {
		vni = req->add_lb.vni;
		if (DP_FAILED(dp_insert_vnf_entry(&vnf_val, DP_VNF_TYPE_LB, vni, 0, ul_addr6))) {
			ret = DP_GRPC_ERR_VNF_INSERT;
			goto err;
		}
		ret = dp_create_lb(&req->add_lb, ul_addr6);
		if (DP_FAILED(ret))
			goto err_vnf;
		if (DP_FAILED(dp_create_vni_route_table(vni, DP_IP_PROTO_IPV4,
					  rte_eth_dev_socket_id(dp_port_get_pf0_id())))
		) {
			ret = DP_GRPC_ERR_VNI_INIT4;
			goto err_lb;
		}
	} else {
		ret = DP_GRPC_ERR_BAD_IPVER;
		goto err;
	}
	rte_memcpy(rep->get_lb.ul_addr6, ul_addr6, sizeof(rep->get_lb.ul_addr6));
	return DP_GRPC_OK;

err_lb:
	dp_delete_lb((void *)req->add_lb.lb_id);
err_vnf:
	dp_del_vnf_with_vnf_key(ul_addr6);
err:
	return ret;
}

static int dp_process_del_lb(dp_request *req, dp_reply *rep)
{
	int ret;

	ret = dp_get_lb((void *)req->del_lb.lb_id, &rep->get_lb);
	if (DP_FAILED(ret))
		return ret;

	dp_del_vnf_with_vnf_key(rep->get_lb.ul_addr6);

	ret = dp_delete_lb((void *)req->del_lb.lb_id);
	if (DP_FAILED(ret))
		return ret;

	if (DP_FAILED(dp_delete_vni_route_table(rep->get_lb.vni, DP_IP_PROTO_IPV4)))
		return DP_GRPC_ERR_VNI_FREE4;

	return DP_GRPC_OK;
}

static int dp_process_get_lb(dp_request *req, dp_reply *rep)
{
	return dp_get_lb((void *)req->del_lb.lb_id, &rep->get_lb);
}

static int dp_process_add_lb_vip(dp_request *req, dp_reply *rep)
{
	if (req->add_lb_vip.ip_type == RTE_ETHER_TYPE_IPV6) {
		return dp_add_lb_back_ip((void *)req->add_lb_vip.lb_id,
								 (uint8_t *)req->add_lb_vip.back.back_addr6,
								 sizeof(req->add_lb_vip.back.back_addr6));
	} else {
		return DP_GRPC_ERR_BAD_IPVER;
	}
}

static int dp_process_del_lb_vip(dp_request *req, dp_reply *rep)
{
	if (req->add_lb_vip.ip_type == RTE_ETHER_TYPE_IPV6) {
		return dp_del_lb_back_ip((void *)req->del_lb_vip.lb_id,
								 (uint8_t *)req->del_lb_vip.back.back_addr6);
	} else {
		return DP_GRPC_ERR_BAD_IPVER;
	}
}

static int dp_process_init(dp_request *req, dp_reply *rep)
{
	dp_del_all_neigh_nat_entries_in_vni(DP_NETWORK_NAT_ALL_VNI);
	return dp_lpm_reset_all_route_tables(rte_eth_dev_socket_id(dp_port_get_pf0_id()));
}

static int dp_process_vni_in_use(dp_request *req, dp_reply *rep)
{
	if (req->vni_in_use.type == DP_VNI_IPV4) {
		rep->vni_in_use.in_use = dp_is_vni_route_tbl_available(req->vni_in_use.vni, DP_IP_PROTO_IPV4,
															   rte_eth_dev_socket_id(dp_port_get_pf0_id()));
	} else
		return DP_GRPC_ERR_WRONG_TYPE;

	return DP_GRPC_OK;
}

static int dp_process_add_fwall_rule(dp_request *req, dp_reply *rep)
{
	int port_id;

	port_id = dp_get_portid_with_vm_handle(req->fw_rule.machine_id);
	if (DP_FAILED(port_id))
		return DP_GRPC_ERR_NO_VM;

	if (dp_get_firewall_rule(req->fw_rule.rule.rule_id, port_id))
		return DP_GRPC_ERR_ALREADY_EXISTS;

	if (req->fw_rule.rule.action == DP_FWALL_DROP)
		return DP_GRPC_ERR_NO_DROP_SUPPORT;

	if (DP_FAILED(dp_add_firewall_rule(&req->fw_rule.rule, port_id)))
		return DP_GRPC_ERR_OUT_OF_MEMORY;

	return DP_GRPC_OK;
}

static int dp_process_get_fwall_rule(dp_request *req, dp_reply *rep)
{
	int port_id;
	struct dp_fwall_rule *rule;

	port_id = dp_get_portid_with_vm_handle(req->fw_rule.machine_id);
	if (DP_FAILED(port_id))
		return DP_GRPC_ERR_NO_VM;

	rule = dp_get_firewall_rule(req->fw_rule.rule.rule_id, port_id);
	if (!rule)
		return DP_GRPC_ERR_NOT_FOUND;

	rep->fw_rule.rule = *rule;
	return DP_GRPC_OK;
}

static int dp_process_del_fwall_rule(dp_request *req, dp_reply *rep)
{
	int port_id;

	port_id = dp_get_portid_with_vm_handle(req->fw_rule.machine_id);
	if (DP_FAILED(port_id))
		return DP_GRPC_ERR_NO_VM;

	if (DP_FAILED(dp_delete_firewall_rule(req->fw_rule.rule.rule_id, port_id)))
		return DP_GRPC_ERR_NOT_FOUND;

	return DP_GRPC_OK;
}

static int dp_process_vni_reset(dp_request *req, dp_reply *rep)
{
	if (req->vni_in_use.type == DP_VNI_BOTH)
		return dp_lpm_reset_route_tables(req->vni_in_use.vni, rte_eth_dev_socket_id(dp_port_get_pf0_id()));
	else
		return DP_GRPC_ERR_WRONG_TYPE;
}

static int dp_process_addvip(dp_request *req, dp_reply *rep)
{
	uint8_t ul_addr6[DP_VNF_IPV6_ADDR_SIZE];
	struct dp_vnf_value vnf_val = {0};
	int port_id;
	uint32_t vm_ip, vm_vni;
	int ret;

	port_id = dp_get_portid_with_vm_handle(req->add_vip.machine_id);
	if (DP_FAILED(port_id)) {
		ret = DP_GRPC_ERR_NO_VM;
		goto err;
	}

	if (req->add_vip.ip_type == RTE_ETHER_TYPE_IPV4) {
		vm_ip = dp_get_dhcp_range_ip4(port_id);
		vm_vni = dp_get_vm_vni(port_id);
		if (DP_FAILED(dp_insert_vnf_entry(&vnf_val, DP_VNF_TYPE_VIP, vm_vni, port_id, ul_addr6))) {
			ret = DP_GRPC_ERR_VNF_INSERT;
			goto err;
		}
		ret = dp_set_vm_snat_ip(vm_ip, ntohl(req->add_vip.vip.vip_addr), vm_vni, ul_addr6);
		if (DP_FAILED(ret))
			goto err_vnf;

		ret = dp_set_dnat_ip(ntohl(req->add_vip.vip.vip_addr), vm_ip, vm_vni);
		if (DP_FAILED(ret))
			goto err_snat;
		rte_memcpy(rep->ul_addr6, ul_addr6, sizeof(rep->ul_addr6));
	} else {
		ret = DP_GRPC_ERR_BAD_IPVER;
		goto err;
	}
	return DP_GRPC_OK;

err_snat:
	dp_del_vm_snat_ip(vm_ip, vm_vni);
err_vnf:
	dp_del_vnf_with_vnf_key(ul_addr6);
err:
	return ret;
}

static int dp_process_delvip(dp_request *req, dp_reply *rep)
{
	int port_id;
	struct snat_data *s_data;
	uint32_t vm_ip, vm_vni;

	port_id = dp_get_portid_with_vm_handle(req->del_machine.machine_id);
	if (DP_FAILED(port_id))
		return DP_GRPC_ERR_NO_VM;

	vm_ip = dp_get_dhcp_range_ip4(port_id);
	vm_vni = dp_get_vm_vni(port_id);

	s_data = dp_get_vm_snat_data(vm_ip, vm_vni);
	if (!s_data || !s_data->vip_ip)
		return DP_GRPC_ERR_SNAT_NO_DATA;

	dp_del_vnf_with_vnf_key(s_data->ul_ip6);

	rep->get_vip.vip.vip_addr = s_data->vip_ip;

	// always delete, i.e. do not use dp_del_vip_from_dnat(),
	// because 1:1 VIP is not shared with anything
	dp_del_dnat_ip(s_data->vip_ip, vm_vni);
	dp_del_vm_snat_ip(vm_ip, vm_vni);

	return DP_GRPC_OK;
}

static int dp_process_getvip(dp_request *req, dp_reply *rep)
{
	int port_id;
	struct snat_data *s_data;

	port_id = dp_get_portid_with_vm_handle(req->del_machine.machine_id);
	if (DP_FAILED(port_id))
		return DP_GRPC_ERR_NO_VM;

	s_data = dp_get_vm_snat_data(dp_get_dhcp_range_ip4(port_id), dp_get_vm_vni(port_id));
	if (!s_data || !s_data->vip_ip)
		return DP_GRPC_ERR_SNAT_NO_DATA;

	rep->get_vip.vip.vip_addr = htonl(s_data->vip_ip);
	rte_memcpy(rep->get_vip.ul_addr6, s_data->ul_ip6, sizeof(rep->ul_addr6));
	return DP_GRPC_OK;
}

static int dp_process_addlb_prefix(dp_request *req, dp_reply *rep)
{
	int port_id;
	struct dp_vnf_value vnf_val = {0};
	uint8_t ul_addr6[DP_VNF_IPV6_ADDR_SIZE];

	port_id = dp_get_portid_with_vm_handle(req->add_pfx.machine_id);
	if (DP_FAILED(port_id))
		return DP_GRPC_ERR_NO_VM;

	vnf_val.alias_pfx.ip = ntohl(req->add_pfx.pfx_ip.pfx_addr);
	vnf_val.alias_pfx.length = req->add_pfx.pfx_length;
	if (DP_FAILED(dp_insert_vnf_entry(&vnf_val, DP_VNF_TYPE_LB_ALIAS_PFX, dp_get_vm_vni(port_id), port_id, ul_addr6)))
		return DP_GRPC_ERR_VNF_INSERT;

	rte_memcpy(rep->route.trgt_ip.addr6, ul_addr6, sizeof(rep->route.trgt_ip.addr6));
	return DP_GRPC_OK;
}

static int dp_process_dellb_prefix(dp_request *req, dp_reply *rep)
{
	int port_id;
	struct dp_vnf_value vnf_val = {0};

	port_id = dp_get_portid_with_vm_handle(req->add_pfx.machine_id);
	if (DP_FAILED(port_id))
		return DP_GRPC_ERR_NO_VM;

	vnf_val.alias_pfx.ip = ntohl(req->add_pfx.pfx_ip.pfx_addr);
	vnf_val.alias_pfx.length = req->add_pfx.pfx_length;
	return dp_remove_vnf_entry(&vnf_val, DP_VNF_TYPE_LB_ALIAS_PFX, port_id);
}

static int dp_process_addprefix(dp_request *req, dp_reply *rep)
{
	uint8_t ul_addr6[DP_VNF_IPV6_ADDR_SIZE];
	int port_id;
	uint32_t vm_vni;
	int socket_id;
	struct dp_vnf_value vnf_val = {0};
	int ret;

	port_id = dp_get_portid_with_vm_handle(req->add_pfx.machine_id);
	if (DP_FAILED(port_id)) {
		ret = DP_GRPC_ERR_NO_VM;
		goto err;
	}

	if (req->add_pfx.pfx_ip_type == RTE_ETHER_TYPE_IPV4) {
		vm_vni = dp_get_vm_vni(port_id);
		socket_id = rte_eth_dev_socket_id(port_id);
		ret = dp_add_route(port_id, vm_vni, 0, ntohl(req->add_pfx.pfx_ip.pfx_addr),
						   NULL, req->add_pfx.pfx_length, socket_id);
		if (DP_FAILED(ret))
			goto err;
		vnf_val.alias_pfx.ip = ntohl(req->add_pfx.pfx_ip.pfx_addr);
		vnf_val.alias_pfx.length = req->add_pfx.pfx_length;
		if (DP_FAILED(dp_insert_vnf_entry(&vnf_val, DP_VNF_TYPE_ALIAS_PFX, vm_vni, port_id, ul_addr6))) {
			ret = DP_GRPC_ERR_VNF_INSERT;
			goto err_vnf;
		}
		rte_memcpy(rep->ul_addr6, ul_addr6, sizeof(rep->ul_addr6));
	} else {
		ret = DP_GRPC_ERR_BAD_IPVER;
		goto err;
	}
	return DP_GRPC_OK;

err_vnf:
	dp_del_route(port_id, vm_vni, 0,
				 ntohl(req->add_pfx.pfx_ip.pfx_addr), NULL,
				 req->add_pfx.pfx_length, socket_id);
err:
	return ret;
}

static int dp_process_delprefix(dp_request *req, dp_reply *rep)
{
	int port_id;
	struct dp_vnf_value vnf_val = {0};
	int ret, ret2;

	port_id = dp_get_portid_with_vm_handle(req->add_pfx.machine_id);
	if (DP_FAILED(port_id))
		return DP_GRPC_ERR_NO_VM;

	if (req->add_pfx.pfx_ip_type == RTE_ETHER_TYPE_IPV4) {
		ret = dp_del_route(port_id, dp_get_vm_vni(port_id), 0,
						   ntohl(req->add_pfx.pfx_ip.pfx_addr), 0,
						   req->add_pfx.pfx_length, rte_eth_dev_socket_id(dp_port_get_pf0_id()));
		// ignore the error and try to delete the vnf entry anyway
	} else
		return DP_GRPC_ERR_BAD_IPVER;

	vnf_val.alias_pfx.ip = ntohl(req->add_pfx.pfx_ip.pfx_addr);
	vnf_val.alias_pfx.length = req->add_pfx.pfx_length;
	ret2 = dp_remove_vnf_entry(&vnf_val, DP_VNF_TYPE_ALIAS_PFX, port_id);
	return DP_FAILED(ret) ? ret : ret2;
}

static int dp_process_addmachine(dp_request *req, dp_reply *rep)
{
	uint8_t ul_addr6[DP_VNF_IPV6_ADDR_SIZE];
	uint16_t port_id = DP_INVALID_PORT_ID;
	struct dp_vnf_value vnf_val = {0};
	int ret = DP_GRPC_OK;
	uint32_t vni = req->add_machine.vni;
	int socket_id;

	// TODO(plague?): this seems to be a misnomer (add_machine.name), this name comes from vm_pci/device argument
	if (req->add_machine.name[0] == '\0'
		|| DP_FAILED(rte_eth_dev_get_port_by_name(req->add_machine.name, &port_id))
	) {
		ret = DP_GRPC_ERR_NOT_FOUND;
		goto err;
	}

	if (port_id == DP_INVALID_PORT_ID) {
		ret = DP_GRPC_ERR_LIMIT_REACHED;
		goto err;
	}

	if (!dp_port_is_vf_free(port_id)) {
		ret = DP_GRPC_ERR_ALREADY_EXISTS;
		// fill the device details anyway so the caller knows which one is already allocated
		// TODO as below, fill in properly
		rep->vf_pci.bus = 2;
		rep->vf_pci.domain = 2;
		rep->vf_pci.function = 2;
		rte_eth_dev_get_name_by_port(port_id, rep->vf_pci.name);
		goto err;
	}

	// can only fail if the port_id is invalid
	socket_id = rte_eth_dev_socket_id(port_id);

	if (DP_FAILED(dp_insert_vnf_entry(&vnf_val, DP_VNF_TYPE_INTERFACE_IP, vni, port_id, ul_addr6))) {
		ret = DP_GRPC_ERR_VNF_INSERT;
		goto err;
	}
	if (DP_FAILED(dp_map_vm_handle(req->add_machine.machine_id, port_id))) {
		ret = DP_GRPC_ERR_VM_HANDLE;
		goto err_vnf;
	}
	if (DP_FAILED(setup_vm(port_id, vni, socket_id))) {
		ret = DP_GRPC_ERR_VNI_INIT4;
		goto handle_err;
	}
	if (DP_FAILED(setup_vm6(port_id, vni, socket_id))) {
		ret = DP_GRPC_ERR_VNI_INIT6;
		goto vm_err;
	}
	dp_set_dhcp_range_ip4(port_id, ntohl(req->add_machine.ip4_addr), DP_LPM_DHCP_IP_DEPTH, socket_id);
	dp_set_vm_pxe_ip4(port_id, ntohl(req->add_machine.ip4_pxe_addr), socket_id);
	dp_set_vm_pxe_str(port_id, req->add_machine.pxe_str);
	dp_set_dhcp_range_ip6(port_id, req->add_machine.ip6_addr6, DP_LPM_DHCP_IP6_DEPTH, socket_id);
	ret = dp_add_route(port_id, vni, 0, ntohl(req->add_machine.ip4_addr), NULL, 32, socket_id);
	if (DP_FAILED(ret))
		goto vm_err;
	ret = dp_add_route6(port_id, vni, 0, req->add_machine.ip6_addr6, NULL, 128, socket_id);
	if (DP_FAILED(ret))
		goto route_err;
	if (DP_FAILED(dp_port_start(port_id))) {
		ret = DP_GRPC_ERR_PORT_START;
		goto route6_err;
	}
	/* TODO get the pci info of this port and fill it accordingly */
	// NOTE: this should be part of dp_port structure so no rte_ call should be needed at this point
	rep->vf_pci.bus = 2;
	rep->vf_pci.domain = 2;
	rep->vf_pci.function = 2;
	rte_eth_dev_get_name_by_port(port_id, rep->vf_pci.name);

	rte_memcpy(dp_get_vm_ul_ip6(port_id), ul_addr6, sizeof(ul_addr6));
	rte_memcpy(rep->vf_pci.ul_addr6, dp_get_vm_ul_ip6(port_id), sizeof(rep->vf_pci.ul_addr6));
	return DP_GRPC_OK;

route6_err:
	dp_del_route6(port_id, vni, 0, req->add_machine.ip6_addr6, NULL, 128, socket_id);
route_err:
	dp_del_route(port_id, vni, 0, ntohl(req->add_machine.ip4_addr), NULL, 32, socket_id);
vm_err:
	dp_del_vm(port_id, socket_id, DP_LPM_ROLLBACK);
handle_err:
	dp_del_portid_with_vm_handle(req->add_machine.machine_id);
err_vnf:
	dp_del_vnf_with_vnf_key(ul_addr6);
err:
	return ret;
}

static int dp_process_delmachine(dp_request *req, dp_reply *rep)
{
	int port_id;
	int ret = DP_GRPC_OK;

	port_id = dp_get_portid_with_vm_handle(req->del_machine.machine_id);
	if (DP_FAILED(port_id))
		return DP_GRPC_ERR_NOT_FOUND;

	dp_del_vnf_with_vnf_key(dp_get_vm_ul_ip6(port_id));
	if (DP_FAILED(dp_port_stop(port_id)))
		ret = DP_GRPC_ERR_PORT_STOP;
	// carry on with cleanup though
	dp_del_portid_with_vm_handle(req->del_machine.machine_id);
	dp_del_vm(port_id, rte_eth_dev_socket_id(port_id), !DP_LPM_ROLLBACK);
#ifdef ENABLE_VIRTSVC
	dp_virtsvc_del_vm(port_id);
#endif
	return ret;
}

static int dp_process_getmachine(dp_request *req, dp_reply *rep)
{
	int port_id;
	dp_vm_info *vm_info;

	port_id = dp_get_portid_with_vm_handle(req->del_machine.machine_id);
	if (DP_FAILED(port_id))
		return DP_GRPC_ERR_NOT_FOUND;

	vm_info = &((&rep->vm_info)[0]);
	vm_info->ip_addr = dp_get_dhcp_range_ip4(port_id);
	rte_memcpy(vm_info->ip6_addr, dp_get_dhcp_range_ip6(port_id), sizeof(vm_info->ip6_addr));
	vm_info->vni = dp_get_vm_vni(port_id);
	rte_memcpy(vm_info->machine_id, dp_get_vm_machineid(port_id), sizeof(vm_info->machine_id));
	rte_eth_dev_get_name_by_port(port_id, rep->vm_info.pci_name);
	rte_memcpy(rep->vm_info.ul_addr6, dp_get_vm_ul_ip6(port_id), sizeof(rep->vm_info.ul_addr6));
	return DP_GRPC_OK;
}

static int dp_process_addroute(dp_request *req, dp_reply *rep)
{
	if (req->route.pfx_ip_type == RTE_ETHER_TYPE_IPV4) {
		return dp_add_route(dp_port_get_pf0_id(), req->route.vni, req->route.trgt_vni,
							ntohl(req->route.pfx_ip.addr), req->route.trgt_ip.addr6,
							req->route.pfx_length, rte_eth_dev_socket_id(dp_port_get_pf0_id()));
	} else if (req->route.pfx_ip_type == RTE_ETHER_TYPE_IPV6) {
		return dp_add_route6(dp_port_get_pf0_id(), req->route.vni, req->route.trgt_vni,
							 req->route.pfx_ip.addr6, req->route.trgt_ip.addr6,
							 req->route.pfx_length, rte_eth_dev_socket_id(dp_port_get_pf0_id()));
	} else
		return DP_GRPC_ERR_BAD_IPVER;
}

static int dp_process_delroute(dp_request *req, dp_reply *rep)
{
	if (req->route.pfx_ip_type == RTE_ETHER_TYPE_IPV4) {
		return dp_del_route(dp_port_get_pf0_id(), req->route.vni, req->route.trgt_vni,
							ntohl(req->route.pfx_ip.addr), req->route.trgt_ip.addr6,
							req->route.pfx_length, rte_eth_dev_socket_id(dp_port_get_pf0_id()));
	} else if (req->route.pfx_ip_type == RTE_ETHER_TYPE_IPV6) {
		return dp_del_route6(dp_port_get_pf0_id(), req->route.vni, req->route.trgt_vni,
							 req->route.pfx_ip.addr6, req->route.trgt_ip.addr6,
							 req->route.pfx_length, rte_eth_dev_socket_id(dp_port_get_pf0_id()));
	} else
		return DP_GRPC_ERR_BAD_IPVER;
}

static int dp_process_addnat(dp_request *req, dp_reply *rep)
{
	uint8_t ul_addr6[DP_VNF_IPV6_ADDR_SIZE];
	struct dp_vnf_value vnf_val = {0};
	int port_id;
	uint32_t vm_ip, vm_vni;
	int ret;

	port_id = dp_get_portid_with_vm_handle(req->add_nat_vip.machine_id);
	if (DP_FAILED(port_id)) {
		ret = DP_GRPC_ERR_NO_VM;
		goto err;
	}

	if (req->add_nat_vip.ip_type == RTE_ETHER_TYPE_IPV4) {
		vm_ip = dp_get_dhcp_range_ip4(port_id);
		vm_vni = dp_get_vm_vni(port_id);
		if (DP_FAILED(dp_insert_vnf_entry(&vnf_val, DP_VNF_TYPE_NAT, vm_vni, port_id, ul_addr6))) {
			ret = DP_GRPC_ERR_VNF_INSERT;
			goto err;
		}
		ret = dp_set_vm_network_snat_ip(vm_ip, ntohl(req->add_nat_vip.vip.vip_addr),
										vm_vni, (uint16_t)req->add_nat_vip.port_range[0],
										(uint16_t)req->add_nat_vip.port_range[1], ul_addr6);
		if (DP_FAILED(ret))
			goto err_vnf;

		ret = dp_set_dnat_ip(ntohl(req->add_nat_vip.vip.vip_addr), 0, vm_vni);
		if (DP_FAILED(ret) && ret != DP_GRPC_ERR_DNAT_EXISTS)
			goto err_dnat;
		rte_memcpy(rep->ul_addr6, ul_addr6, sizeof(rep->ul_addr6));
	} else {
		ret = DP_GRPC_ERR_BAD_IPVER;
		goto err;
	}
	return DP_GRPC_OK;

err_dnat:
	dp_del_vm_network_snat_ip(vm_ip, vm_vni);
err_vnf:
	dp_del_vnf_with_vnf_key(ul_addr6);
err:
	return ret;

}

static int dp_process_delnat(dp_request *req, dp_reply *rep)
{
	int port_id;
	struct snat_data *s_data;
	uint32_t vm_ip, vm_vni;

	port_id = dp_get_portid_with_vm_handle(req->del_nat_vip.machine_id);
	if (DP_FAILED(port_id))
		return DP_GRPC_ERR_NO_VM;

	vm_ip = dp_get_dhcp_range_ip4(port_id);
	vm_vni = dp_get_vm_vni(port_id);

	s_data = dp_get_vm_snat_data(vm_ip, vm_vni);
	if (!s_data || !s_data->network_nat_ip)
		return DP_GRPC_ERR_SNAT_NO_DATA;

	dp_del_vnf_with_vnf_key(s_data->ul_nat_ip6);

	rep->get_vip.vip.vip_addr = s_data->network_nat_ip;
	dp_del_vip_from_dnat(s_data->network_nat_ip, vm_vni);

	return dp_del_vm_network_snat_ip(vm_ip, vm_vni);
}

static int dp_process_getnat(dp_request *req, dp_reply *rep)
{
	int port_id;
	struct snat_data *s_data;

	port_id = dp_get_portid_with_vm_handle(req->del_machine.machine_id);
	if (DP_FAILED(port_id))
		return DP_GRPC_ERR_NO_VM;

	s_data = dp_get_vm_snat_data(dp_get_dhcp_range_ip4(port_id), dp_get_vm_vni(port_id));
	if (!s_data || !s_data->network_nat_ip)
		return DP_GRPC_ERR_SNAT_NO_DATA;

	rep->nat_entry.m_ip.addr = htonl(s_data->network_nat_ip);
	rep->nat_entry.min_port = s_data->network_nat_port_range[0];
	rep->nat_entry.max_port = s_data->network_nat_port_range[1];
	rte_memcpy(rep->nat_entry.underlay_route, s_data->ul_nat_ip6, sizeof(rep->nat_entry.underlay_route));
	return DP_GRPC_OK;
}

static int dp_process_add_neigh_nat(dp_request *req, dp_reply *rep)
{
	int ret;

	if (req->add_nat_neigh.type != DP_NETNAT_INFO_TYPE_NEIGHBOR)
		return DP_GRPC_ERR_WRONG_TYPE;

	if (req->add_nat_neigh.ip_type == RTE_ETHER_TYPE_IPV4) {
		ret = dp_add_network_nat_entry(ntohl(req->add_nat_neigh.vip.vip_addr), NULL,
									   req->add_nat_neigh.vni,
									   (uint16_t)req->add_nat_neigh.port_range[0],
									   (uint16_t)req->add_nat_neigh.port_range[1],
									   req->add_nat_neigh.route);
		if (DP_FAILED(ret))
			return ret;

		ret = dp_set_dnat_ip(ntohl(req->add_nat_neigh.vip.vip_addr), 0, req->add_nat_neigh.vni);
		if (DP_FAILED(ret) && ret != DP_GRPC_ERR_DNAT_EXISTS)
			return ret;
	} else
		return DP_GRPC_ERR_BAD_IPVER;

	return DP_GRPC_OK;
}

static int dp_process_del_neigh_nat(dp_request *req, dp_reply *rep)
{
	int ret;

	if (req->del_nat_neigh.type != DP_NETNAT_INFO_TYPE_NEIGHBOR)
		return DP_GRPC_ERR_WRONG_TYPE;

	if (req->del_nat_vip.ip_type == RTE_ETHER_TYPE_IPV4) {
		ret = dp_del_network_nat_entry(ntohl(req->del_nat_vip.vip.vip_addr), NULL,
									   req->del_nat_vip.vni,
									   (uint16_t)req->del_nat_vip.port_range[0],
									   (uint16_t)req->del_nat_vip.port_range[1]);
		if (DP_FAILED(ret))
			return ret;

		dp_del_vip_from_dnat(ntohl(req->del_nat_vip.vip.vip_addr), req->del_nat_vip.vni);
	} else
		return DP_GRPC_ERR_BAD_IPVER;

	return DP_GRPC_OK;

}

static int dp_process_listmachine(dp_request *req, struct rte_mbuf *m, struct rte_mbuf *rep_arr[])
{
	int8_t rep_arr_size = DP_MBUF_ARR_SIZE;
	struct rte_mbuf *m_new, *m_curr = m;
	int act_ports[DP_MAX_PORTS];
	uint16_t msg_per_buf;
	dp_vm_info *vm_info;
	dp_reply *rep;
	int count;

	count = dp_get_active_vm_ports(act_ports);
	msg_per_buf = dp_first_mbuf_to_grpc_arr(m_curr, rep_arr, &rep_arr_size, sizeof(dp_vm_info));

	if (!count)
		goto out;

	rep = rte_pktmbuf_mtod(m_curr, dp_reply*);
	for (int i = 0; i < count; ++i) {
		if (rep->com_head.msg_count &&
			(rep->com_head.msg_count % msg_per_buf == 0)) {
			m_new = dp_add_mbuf_to_grpc_arr(m_curr, rep_arr, &rep_arr_size);
			if (!m_new)
				break;
			m_curr = m_new;
			rep = rte_pktmbuf_mtod(m_new, dp_reply*);
		}
		rep->com_head.msg_count++;
		vm_info = &((&rep->vm_info)[i % msg_per_buf]);
		vm_info->ip_addr = dp_get_dhcp_range_ip4(act_ports[i]);
		rte_memcpy(vm_info->ip6_addr, dp_get_dhcp_range_ip6(act_ports[i]),
				   sizeof(vm_info->ip6_addr));
		vm_info->vni = dp_get_vm_vni(act_ports[i]);
		rte_memcpy(vm_info->machine_id, dp_get_vm_machineid(act_ports[i]),
			sizeof(vm_info->machine_id));
		rte_eth_dev_get_name_by_port(act_ports[i], vm_info->pci_name);
		rte_memcpy(vm_info->ul_addr6, dp_get_vm_ul_ip6(act_ports[i]), sizeof(vm_info->ul_addr6));
	}
	if (rep_arr_size < 0) {
		dp_last_mbuf_from_grpc_arr(m_curr, rep_arr);
		return DP_GRPC_OK;
	}

out:
	rep_arr[--rep_arr_size] = m_curr;
	return DP_GRPC_OK;
}

static int dp_process_listroute(dp_request *req, struct rte_mbuf *m, struct rte_mbuf *rep_arr[])
{
	dp_list_routes(req->route.vni, m, rte_eth_dev_socket_id(dp_port_get_pf0_id()), 0, rep_arr, DP_SHOW_EXT_ROUTES);
	return DP_GRPC_OK;
}

static int dp_process_listbackips(dp_request *req, struct rte_mbuf *m, struct rte_mbuf *rep_arr[])
{
	dp_reply *rep = rte_pktmbuf_mtod(m, dp_reply *);
	int ret;

	ret = dp_get_lb_back_ips((void *)req->qry_lb_vip.lb_id, rep);

	rep_arr[DP_MBUF_ARR_SIZE - 1] = m;
	return ret;
}

static int dp_process_listfwall_rules(dp_request *req, struct rte_mbuf *m, struct rte_mbuf *rep_arr[])
{
	int port_id;

	port_id = dp_get_portid_with_vm_handle(req->fw_rule.machine_id);
	if (DP_FAILED(port_id)) {
		rep_arr[DP_MBUF_ARR_SIZE - 1] = m;
		return DP_GRPC_ERR_NO_VM;
	}

	dp_list_firewall_rules(port_id, m, rep_arr);
	return DP_GRPC_OK;
}

static int dp_process_listlb_pfxs(dp_request *req, struct rte_mbuf *m, struct rte_mbuf *rep_arr[])
{
	int port_id;

	port_id = dp_get_portid_with_vm_handle(req->get_pfx.machine_id);
	if (DP_FAILED(port_id)) {
		rep_arr[DP_MBUF_ARR_SIZE - 1] = m;
		return DP_GRPC_ERR_NO_VM;
	}

	dp_list_vnf_alias_routes(m, port_id, DP_VNF_TYPE_LB_ALIAS_PFX, rep_arr);
	return DP_GRPC_OK;
}

static int dp_process_listpfxs(dp_request *req, struct rte_mbuf *m, struct rte_mbuf *rep_arr[])
{
	int port_id;

	port_id = dp_get_portid_with_vm_handle(req->get_pfx.machine_id);
	if (port_id < 0) {
		rep_arr[DP_MBUF_ARR_SIZE - 1] = m;
		return DP_GRPC_ERR_NO_VM;
	}

	dp_list_vnf_alias_routes(m, port_id, DP_VNF_TYPE_ALIAS_PFX, rep_arr);
	return DP_GRPC_OK;
}

static int dp_process_getnatentry(dp_request *req, struct rte_mbuf *m, struct rte_mbuf *rep_arr[])
{
	int ret;

	if (req->get_nat_entry.ip_type == RTE_ETHER_TYPE_IPV4) {
		if (req->get_nat_entry.type == DP_NETNAT_INFO_TYPE_LOCAL)
			ret = dp_list_nat_local_entry(m, rep_arr, ntohl(req->get_nat_entry.vip.vip_addr));
		else if (req->get_nat_entry.type == DP_NETNAT_INFO_TYPE_NEIGHBOR)
			ret = dp_list_nat_neigh_entry(m, rep_arr, ntohl(req->get_nat_entry.vip.vip_addr));
		else
			return DP_GRPC_ERR_WRONG_TYPE;
		return DP_FAILED(ret) ? DP_GRPC_ERR_ITERATOR : DP_GRPC_OK;
	} else {
		return DP_GRPC_ERR_BAD_IPVER;
	}
}

void dp_process_request(struct rte_mbuf *m)
{
	struct rte_mbuf *m_arr[DP_MBUF_ARR_SIZE];
	dp_request *req;
	dp_reply rep, *p_rep;
	int ret;

	req = rte_pktmbuf_mtod(m, dp_request *);
	memset(&rep, 0, sizeof(dp_reply));
	memset(m_arr, 0, DP_MBUF_ARR_SIZE * sizeof(struct rte_mbuf *));

	switch (req->com_head.com_type) {
	case DP_REQ_TYPE_INIT:
		ret = dp_process_init(req, &rep);
		break;
	case DP_REQ_TYPE_IS_VNI_IN_USE:
		ret = dp_process_vni_in_use(req, &rep);
		break;
	case DP_REQ_TYPE_VNI_RESET:
		ret = dp_process_vni_reset(req, &rep);
		break;
	case DP_REQ_TYPE_CREATELB:
		ret = dp_process_add_lb(req, &rep);
		break;
	case DP_REQ_TYPE_GETLB:
		ret = dp_process_get_lb(req, &rep);
		break;
	case DP_REQ_TYPE_DELLB:
		ret = dp_process_del_lb(req, &rep);
		break;
	case DP_REQ_TYPE_ADDLBVIP:
		ret = dp_process_add_lb_vip(req, &rep);
		break;
	case DP_REQ_TYPE_DELLBVIP:
		ret = dp_process_del_lb_vip(req, &rep);
		break;
	case DP_REQ_TYPE_ADDVIP:
		ret = dp_process_addvip(req, &rep);
		break;
	case DP_REQ_TYPE_DELVIP:
		ret = dp_process_delvip(req, &rep);
		break;
	case DP_REQ_TYPE_GETVIP:
		ret = dp_process_getvip(req, &rep);
		break;
	case DP_REQ_TYPE_ADDPREFIX:
		ret = dp_process_addprefix(req, &rep);
		break;
	case DP_REQ_TYPE_DELPREFIX:
		ret = dp_process_delprefix(req, &rep);
		break;
	case DP_REQ_TYPE_ADDLBPREFIX:
		ret = dp_process_addlb_prefix(req, &rep);
		break;
	case DP_REQ_TYPE_DELLBPREFIX:
		ret = dp_process_dellb_prefix(req, &rep);
		break;
	case DP_REQ_TYPE_ADDMACHINE:
		ret = dp_process_addmachine(req, &rep);
		break;
	case DP_REQ_TYPE_DELMACHINE:
		ret = dp_process_delmachine(req, &rep);
		break;
	case DP_REQ_TYPE_GETMACHINE:
		ret = dp_process_getmachine(req, &rep);
		break;
	case DP_REQ_TYPE_ADDROUTE:
		ret = dp_process_addroute(req, &rep);
		break;
	case DP_REQ_TYPE_DELROUTE:
		ret = dp_process_delroute(req, &rep);
		break;
	case DP_REQ_TYPE_LISTROUTE:
		ret = dp_process_listroute(req, m, m_arr);
		break;
	case DP_REQ_TYPE_ADD_NATVIP:
		ret = dp_process_addnat(req, &rep);
		break;
	case DP_REQ_TYPE_GET_NATENTRY:
		ret = dp_process_getnatentry(req, m, m_arr);
		break;
	case DP_REQ_TYPE_DEL_NATVIP:
		ret = dp_process_delnat(req, &rep);
		break;
	case DP_REQ_TYPE_GET_NATVIP:
		ret = dp_process_getnat(req, &rep);
		break;
	case DP_REQ_TYPE_ADD_NEIGH_NAT:
		ret = dp_process_add_neigh_nat(req, &rep);
		break;
	case DP_REQ_TYPE_DEL_NEIGH_NAT:
		ret = dp_process_del_neigh_nat(req, &rep);
		break;
	case DP_REQ_TYPE_LISTPREFIX:
		ret = dp_process_listpfxs(req, m, m_arr);
		break;
	case DP_REQ_TYPE_LISTLBPREFIX:
		ret = dp_process_listlb_pfxs(req, m, m_arr);
		break;
	case DP_REQ_TYPE_LIST_FWALL_RULES:
		ret = dp_process_listfwall_rules(req, m, m_arr);
		break;
	case DP_REQ_TYPE_LISTLBBACKENDS:
		ret = dp_process_listbackips(req, m, m_arr);
		break;
	case DP_REQ_TYPE_LISTMACHINE:
		ret = dp_process_listmachine(NULL, m, m_arr);
		break;
	case DP_REQ_TYPE_ADD_FWALL_RULE:
		ret = dp_process_add_fwall_rule(req, &rep);
		break;
	case DP_REQ_TYPE_DEL_FWALL_RULE:
		ret = dp_process_del_fwall_rule(req, &rep);
		break;
	case DP_REQ_TYPE_GET_FWALL_RULE:
		ret = dp_process_get_fwall_rule(req, &rep);
		break;
	default:
		ret = DP_GRPC_ERR_BAD_REQUEST;
		break;
	}
	if (DP_FAILED(ret)) {
		// as gRPC errors are explicitely defined due to API reasons
		// extract the proper value from the standard (negative) retvals
		ret = dp_errcode_to_grpc_errcode(ret);
		DPGRPC_LOG_WARNING("Failed request", DP_LOG_GRPCRET(ret), DP_LOG_GRPCERR(ret));
	}
	rep.com_head.err_code = ret;

	/* For requests without any parameter (like listmachine), the reply */
	/* is directly written into the mbuf in the process function */
	// TODO create direct/array boolean?!
	if (req->com_head.com_type != DP_REQ_TYPE_LISTMACHINE &&
		req->com_head.com_type != DP_REQ_TYPE_LISTROUTE &&
		req->com_head.com_type != DP_REQ_TYPE_LISTPREFIX &&
		req->com_head.com_type != DP_REQ_TYPE_LISTLBPREFIX &&
		req->com_head.com_type != DP_REQ_TYPE_LIST_FWALL_RULES &&
		req->com_head.com_type != DP_REQ_TYPE_LISTLBBACKENDS &&
		req->com_head.com_type != DP_REQ_TYPE_GET_NATENTRY
	) {
		rep.com_head.com_type = req->com_head.com_type;
		p_rep = rte_pktmbuf_mtod(m, dp_reply*);
		*p_rep = rep;
		rte_ring_sp_enqueue(get_dpdk_layer()->grpc_rx_queue, m);
	} else {
		for (int i = DP_MBUF_ARR_SIZE - 1; i >= 0; --i) {
			if (m_arr[i])
				rte_ring_sp_enqueue(get_dpdk_layer()->grpc_rx_queue, m_arr[i]);
		}
	}
}
