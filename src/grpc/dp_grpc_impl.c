#include "dp_lpm.h"
#include "dp_nat.h"
#include "dp_lb.h"
#include <dp_error.h>
#include "grpc/dp_grpc_impl.h"
#include "dpdk_layer.h"

#define DP_SHOW_EXT_ROUTES true
#define DP_SHOW_INT_ROUTES false

int dp_send_to_worker(dp_request *req)
{
	struct rte_mbuf *m = rte_pktmbuf_alloc(get_dpdk_layer()->rte_mempool);
	dp_request *head = rte_pktmbuf_mtod(m, dp_request*);

	*head = *req;

	if (rte_ring_sp_enqueue(get_dpdk_layer()->grpc_tx_queue, m))
		return EXIT_FAILURE;

	return EXIT_SUCCESS;
}

int dp_recv_from_worker(dp_reply *rep)
{
	struct rte_mbuf *m;
	dp_reply *head;

	if (!rte_ring_sc_dequeue(get_dpdk_layer()->grpc_rx_queue, (void**)&m)) {
		head = rte_pktmbuf_mtod(m, dp_reply*);
		*rep = *head;
		rte_pktmbuf_free(m);
		return EXIT_SUCCESS;
	}
	return EXIT_FAILURE;
}

int dp_recv_from_worker_with_mbuf(struct rte_mbuf **mbuf)
{
	struct rte_mbuf *m;

	if (!rte_ring_sc_dequeue(get_dpdk_layer()->grpc_rx_queue, (void**)&m)) {
		*mbuf = m;
		return EXIT_SUCCESS;
	}

	return EXIT_FAILURE;
}

__rte_always_inline void dp_fill_head(dp_com_head* head, uint16_t type,
									  uint8_t is_chained, uint8_t count)
{
	head->com_type = type;
	head->buf_count = count;
	head->is_chained = is_chained;
	head->msg_count = 0;
	head->err_code = EXIT_SUCCESS;
}

static int dp_process_add_lb_vip(dp_request *req, dp_reply *rep)
{
	int ret = EXIT_SUCCESS;

	if (!dp_is_vni_available(req->add_lb_vip.vni,
							 rte_eth_dev_socket_id(dp_get_pf0_port_id()))) {
		ret = DP_ERROR_VM_ADD_LB_NO_VNI_EXIST;
		goto err;
	}
	if (req->add_lb_vip.ip_type == RTE_ETHER_TYPE_IPV4) {
		if (dp_set_lb_back_ip(ntohl(req->add_lb_vip.vip.vip_addr),
						  ntohl(req->add_lb_vip.back.back_addr), req->add_lb_vip.vni)) {
			ret = DP_ERROR_VM_ADD_LB_VIP;
			goto err;
		}
	} else {
		ret = DP_ERROR_VM_ADD_LB_UNSUPP_IP;
		goto err;
	}
	return EXIT_SUCCESS;
err:
	rep->com_head.err_code = ret;
	return ret;
}

static int dp_process_del_lb_vip(dp_request *req, dp_reply *rep)
{
	int ret = EXIT_SUCCESS;

	if (!dp_is_vni_available(req->add_lb_vip.vni,
							 rte_eth_dev_socket_id(dp_get_pf0_port_id()))) {
		ret = DP_ERROR_VM_DEL_LB_NO_VNI_EXIST;
		goto err;
	}
	if (req->add_lb_vip.ip_type == RTE_ETHER_TYPE_IPV4) {
		if (dp_del_lb_back_ip(ntohl(req->add_lb_vip.vip.vip_addr),
						  ntohl(req->add_lb_vip.back.back_addr), req->add_lb_vip.vni)) {
			ret = DP_ERROR_VM_DEL_LB_VIP;
			goto err;
		}
	} else {
		ret = DP_ERROR_VM_DEL_LB_UNSUPP_IP;
		goto err;
	}
	return EXIT_SUCCESS;
err:
	rep->com_head.err_code = ret;
	return ret;
}

static int dp_process_addvip(dp_request *req, dp_reply *rep)
{
	int port_id, ret = EXIT_SUCCESS;

	port_id = dp_get_portid_with_vm_handle(req->add_vip.machine_id);

	/* This machine ID doesnt exist */
	if (port_id < 0) {
		ret = DP_ERROR_VM_ADD_NAT;
		goto err;
	}

	if (req->add_vip.ip_type == RTE_ETHER_TYPE_IPV4) {
		ret = dp_set_vm_snat_ip(dp_get_dhcp_range_ip4(port_id),
						  ntohl(req->add_vip.vip.vip_addr),
						  dp_get_vm_vni(port_id));
		if (ret)
			goto err;
		ret = dp_set_vm_dnat_ip(ntohl(req->add_vip.vip.vip_addr),
						  dp_get_dhcp_range_ip4(port_id),
						  dp_get_vm_vni(port_id));
		if (ret)
			goto err_snat;
	}
	rep->vni = dp_get_vm_vni(port_id);
	return EXIT_SUCCESS;
err_snat:
	dp_del_vm_snat_ip(dp_get_dhcp_range_ip4(port_id), dp_get_vm_vni(port_id));
err:
	rep->com_head.err_code = ret;
	return ret;
}

static int dp_process_delvip(dp_request *req, dp_reply *rep)
{
	int port_id, ret = EXIT_SUCCESS;
	u_int32_t vip;

	port_id = dp_get_portid_with_vm_handle(req->del_machine.machine_id);

	/* This machine ID doesnt exist */
	if (port_id < 0) {
		ret = DP_ERROR_VM_DEL_NAT;
		goto err;
	}

	vip = dp_get_vm_snat_ip(dp_get_dhcp_range_ip4(port_id),
							dp_get_vm_vni(port_id));
	dp_del_vm_snat_ip(dp_get_dhcp_range_ip4(port_id), dp_get_vm_vni(port_id));
	dp_del_vm_dnat_ip(vip, dp_get_vm_vni(port_id));

	return ret;
err:
	rep->com_head.err_code = ret;
	return ret;
}

static int dp_process_getvip(dp_request *req, dp_reply *rep)
{
	int port_id, ret = EXIT_SUCCESS;;

	port_id = dp_get_portid_with_vm_handle(req->del_machine.machine_id);

	/* This machine ID doesnt exist */
	if (port_id < 0) {
		ret = DP_ERROR_VM_GET_NAT;
		goto err;
	}

	rep->get_vip.vip.vip_addr = htonl(dp_get_vm_snat_ip(dp_get_dhcp_range_ip4(port_id),
														dp_get_vm_vni(port_id)));

	if (!rep->get_vip.vip.vip_addr) {
		ret = DP_ERROR_VM_GET_NAT_NO_IP_SET;
		goto err;
	}

	return ret;
err:
	rep->com_head.err_code = ret;
	return ret;
}

static int dp_process_addprefix(dp_request *req, dp_reply *rep)
{
	int port_id, ret = EXIT_SUCCESS;

	port_id = dp_get_portid_with_vm_handle(req->add_pfx.machine_id);

	/* This machine ID doesnt exist */
	if (port_id < 0) {
		ret = DP_ERROR_VM_ADD_PFX_NO_VM;
		goto err;
	}

	if (req->add_pfx.pfx_ip_type == RTE_ETHER_TYPE_IPV4) {
		if (dp_add_route(port_id, dp_get_vm_vni(port_id), 0, ntohl(req->add_pfx.pfx_ip.pfx_addr), 
					 NULL, req->add_pfx.pfx_length, rte_eth_dev_socket_id(port_id))) {
			ret = DP_ERROR_VM_ADD_PFX_ROUTE;
			goto err;
		}
	}
	rep->vni = dp_get_vm_vni(port_id);
	return EXIT_SUCCESS;
err:
	rep->com_head.err_code = ret;
	return ret;
}

static int dp_process_delprefix(dp_request *req, dp_reply *rep)
{
	int port_id, ret = EXIT_SUCCESS;

	port_id = dp_get_portid_with_vm_handle(req->add_pfx.machine_id);

	/* This machine ID doesnt exist */
	if (port_id < 0) {
		ret = DP_ERROR_VM_DEL_PFX_NO_VM;
		goto err;
	}

	if(req->add_pfx.pfx_ip_type == RTE_ETHER_TYPE_IPV4) {
		if (dp_del_route(dp_get_pf0_port_id(), dp_get_vm_vni(port_id), 0,
					 ntohl(req->add_pfx.pfx_ip.pfx_addr), 0,
					 req->add_pfx.pfx_length, rte_eth_dev_socket_id(dp_get_pf0_port_id()))) {
			ret = DP_ERROR_VM_DEL_PFX;
			goto err;
		}
	}

	return ret;
err:
	rep->com_head.err_code = ret;
	return ret;
}

static int dp_process_addmachine(dp_request *req, dp_reply *rep)
{
	struct dp_port_ext pf_port;
	int port_id, err_code = EXIT_SUCCESS;

	memset(&pf_port, 0, sizeof(pf_port));
	memcpy(pf_port.port_name, dp_get_pf0_name(), IFNAMSIZ);

	port_id = dp_get_next_avail_vf_id(get_dpdk_layer(), DP_PORT_VF);
	if ( port_id >= 0) {
		if (dp_map_vm_handle(req->add_machine.machine_id, port_id)) {
			err_code = DP_ERROR_VM_ADD_VM_NAME_ERR;
			goto err;
		}
		if (setup_lpm(port_id, req->add_machine.vni, rte_eth_dev_socket_id(port_id))) {
			err_code = DP_ERROR_VM_ADD_VM_LPM4;
			goto handle_err;
		}
		if (setup_lpm6(port_id, req->add_machine.vni, rte_eth_dev_socket_id(port_id))) {
			err_code = DP_ERROR_VM_ADD_VM_LPM6;
			goto lpm_err;
		}
		dp_set_dhcp_range_ip4(port_id, ntohl(req->add_machine.ip4_addr), 32, 
							  rte_eth_dev_socket_id(port_id));
		dp_set_vm_pxe_ip4(port_id, ntohl(req->add_machine.ip4_pxe_addr),
							  rte_eth_dev_socket_id(port_id));
		dp_set_vm_pxe_str(port_id, req->add_machine.pxe_str);
		dp_set_dhcp_range_ip6(port_id, req->add_machine.ip6_addr6, 128,
							  rte_eth_dev_socket_id(port_id));
		if (dp_add_route(port_id, req->add_machine.vni, 0, ntohl(req->add_machine.ip4_addr), 
					 NULL, 32, rte_eth_dev_socket_id(port_id))) {
			err_code = DP_ERROR_VM_ADD_VM_ADD_ROUT4;
			goto lpm_err;
		}
		if (dp_add_route6(port_id, req->add_machine.vni, 0, req->add_machine.ip6_addr6,
					  NULL, 128, rte_eth_dev_socket_id(port_id))) {
			err_code = DP_ERROR_VM_ADD_VM_ADD_ROUT6;
			goto route_err;
		}
		dp_start_interface(&pf_port, DP_PORT_VF);

		/* TODO get the pci info of this port and fill it accordingly */
		rep->vf_pci.bus = 2;
		rep->vf_pci.domain = 2;
		rep->vf_pci.function = 2;
		rte_eth_dev_get_name_by_port(port_id, rep->vf_pci.name);
	} else {
		err_code = DP_ERROR_VM_ADD_VM_NO_VFS;
		goto err;
	}
	return EXIT_SUCCESS;
/* Rollback the changes, in case of an error */
route_err:
	dp_del_route(port_id, req->add_machine.vni, 0,
				ntohl(req->route.pfx_ip.addr), NULL,
				32, rte_eth_dev_socket_id(port_id));
lpm_err:
	dp_del_vm(port_id, rte_eth_dev_socket_id(port_id), DP_LPM_ROLLBACK);
handle_err:
	dp_del_portid_with_vm_handle(req->add_machine.machine_id);
err:
	rep->com_head.err_code = err_code;
	return EXIT_FAILURE;
}

static int dp_process_delmachine(dp_request *req, dp_reply *rep)
{
	int port_id, ret = EXIT_SUCCESS;

	port_id = dp_get_portid_with_vm_handle(req->del_machine.machine_id);

	/* This machine ID doesnt exist */
	if (port_id < 0) {
		ret = DP_ERROR_VM_DEL_VM_NOT_FND;
		goto err;
	}

	dp_stop_interface(port_id, DP_PORT_VF);
	dp_del_portid_with_vm_handle(req->del_machine.machine_id);
	dp_del_vm(port_id, rte_eth_dev_socket_id(port_id), !DP_LPM_ROLLBACK);
	return ret;
err:
	rep->com_head.err_code = ret;
	return ret;
}

static int dp_process_addroute(dp_request *req, dp_reply *rep)
{
	int ret = EXIT_SUCCESS;

	if(req->route.pfx_ip_type == RTE_ETHER_TYPE_IPV4) {
		if (dp_add_route(dp_get_pf0_port_id(), req->route.vni, req->route.trgt_vni,
					 ntohl(req->route.pfx_ip.addr), req->route.trgt_ip.addr6,
					 req->route.pfx_length, rte_eth_dev_socket_id(dp_get_pf0_port_id()))) {
			ret = DP_ERROR_VM_ADD_RT_FAIL4;
			goto err;
		}
	} else {
		if (dp_add_route6(dp_get_pf0_port_id(), req->route.vni, req->route.trgt_vni,
					  req->route.pfx_ip.addr6, req->route.trgt_ip.addr6,
					  req->route.pfx_length, rte_eth_dev_socket_id(dp_get_pf0_port_id()))) {
			ret = DP_ERROR_VM_ADD_RT_FAIL6;
			goto err;
		}
	}
	return ret;
err:
	rep->com_head.err_code = ret;
	return ret;
}

static int dp_process_delroute(dp_request *req, dp_reply *rep)
{
	int ret = EXIT_SUCCESS;

	if(req->route.pfx_ip_type == RTE_ETHER_TYPE_IPV4) {
		if (dp_del_route(dp_get_pf0_port_id(), req->route.vni, req->route.trgt_vni,
					 ntohl(req->route.pfx_ip.addr), req->route.trgt_ip.addr6,
					 req->route.pfx_length, rte_eth_dev_socket_id(dp_get_pf0_port_id()))) {
			ret = DP_ERROR_VM_DEL_RT;
			goto err;
		}
	} else {
		if (dp_del_route6(dp_get_pf0_port_id(), req->route.vni, req->route.trgt_vni,
					  req->route.pfx_ip.addr6, req->route.trgt_ip.addr6,
					  req->route.pfx_length, rte_eth_dev_socket_id(dp_get_pf0_port_id()))) {
			ret = DP_ERROR_VM_DEL_RT;
			goto err;
		}
	}

	return ret;
err:
	rep->com_head.err_code = ret;
	return ret;
}

static int dp_process_listmachine(dp_request *req, dp_reply *rep)
{
	int act_ports[DP_MAX_PORTS];
	dp_vm_info *vm_info;
	int i, count;

	count = dp_get_active_vm_ports(act_ports);

	if (!count)
		return EXIT_SUCCESS;
	/* TODO in case the reply extends a single mbuf, we should send several mbufs and chain them */
	rep->com_head.msg_count = count;
	for (i = 0; i < count; i++) {
		vm_info = &((&rep->vm_info)[i]);
		vm_info->ip_addr = dp_get_dhcp_range_ip4(act_ports[i]);
		rte_memcpy(vm_info->ip6_addr, dp_get_dhcp_range_ip6(act_ports[i]),
				   sizeof(vm_info->ip6_addr));
		vm_info->vni = dp_get_vm_vni(act_ports[i]);
		rte_memcpy(vm_info->machine_id, dp_get_vm_machineid(act_ports[i]),
			sizeof(vm_info->machine_id));
	}
	return EXIT_SUCCESS;
}

static int dp_process_listroute(dp_request *req, dp_reply *rep)
{
	uint32_t vni = req->route.vni;

	dp_list_routes(vni, rep, rte_eth_dev_socket_id(dp_get_pf0_port_id()), DP_SHOW_EXT_ROUTES);

	return EXIT_SUCCESS;
}

static int dp_process_listbackips(dp_request *req, dp_reply *rep)
{

	dp_get_lb_back_ips(ntohl(req->qry_lb_vip.vip.vip_addr), req->qry_lb_vip.vni, rep);

	return EXIT_SUCCESS;
}

static int dp_process_listpfxs(dp_request *req, dp_reply *rep)
{
	int port_id;

	port_id = dp_get_portid_with_vm_handle(req->get_pfx.machine_id);

	/* This machine ID doesnt exist */
	if (port_id < 0)
		goto out;

	dp_list_routes(dp_get_vm_vni(port_id), rep, 
								rte_eth_dev_socket_id(dp_get_pf0_port_id()), DP_SHOW_INT_ROUTES);

out:
	return EXIT_SUCCESS;
}

int dp_process_request(struct rte_mbuf *m)
{
	dp_request* req;
	dp_reply rep, *p_rep;
	int ret = EXIT_SUCCESS;

	req = rte_pktmbuf_mtod(m, dp_request*);
	memset(&rep, 0, sizeof(dp_reply));

	switch (req->com_head.com_type)
	{
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
		case DP_REQ_TYPE_ADDMACHINE:
			ret = dp_process_addmachine(req, &rep);
			break;
		case DP_REQ_TYPE_DELMACHINE:
			ret = dp_process_delmachine(req, &rep);
			break;
		case DP_REQ_TYPE_ADDROUTE:
			ret = dp_process_addroute(req, &rep);
			break;
		case DP_REQ_TYPE_DELROUTE:
			ret = dp_process_delroute(req, &rep);
			break;
		case DP_REQ_TYPE_LISTROUTE:
			ret = dp_process_listroute(req, rte_pktmbuf_mtod(m, dp_reply*));
			break;
		case DP_REQ_TYPE_LISTPREFIX:
			ret = dp_process_listpfxs(req, rte_pktmbuf_mtod(m, dp_reply*));
			break;
		case DP_REQ_TYPE_LISTLBBACKENDS:
			ret = dp_process_listbackips(req, rte_pktmbuf_mtod(m, dp_reply*));
			break;
		case DP_REQ_TYPE_LISTMACHINE:
			ret = dp_process_listmachine(NULL, rte_pktmbuf_mtod(m, dp_reply*));
			break;
		default:
			break;
	}
	/* For requests without any parameter (like listmachine), the reply */
	/* is directly written into the mbuf in the process function */
	if (req->com_head.com_type != DP_REQ_TYPE_LISTMACHINE &&
		req->com_head.com_type != DP_REQ_TYPE_LISTROUTE && 
		req->com_head.com_type != DP_REQ_TYPE_LISTPREFIX && 
		req->com_head.com_type != DP_REQ_TYPE_LISTLBBACKENDS) {
		rep.com_head.com_type = req->com_head.com_type;
		p_rep = rte_pktmbuf_mtod(m, dp_reply*);
		*p_rep = rep;
	}
	rte_ring_sp_enqueue(get_dpdk_layer()->grpc_rx_queue, m);

	return ret;
}