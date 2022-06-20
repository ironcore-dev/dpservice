#include "grpc/dp_async_grpc.h"
#include "grpc/dp_grpc_service.h"
#include "grpc/dp_grpc_impl.h"
#include <arpa/inet.h>
#include <rte_mbuf.h>
#include <dp_error.h>
#include <rte_ether.h>

int InitializedCall::Proceed()
{
	grpc::Status ret = grpc::Status::OK;

	if (status_ == REQUEST) {
		new InitializedCall(service_, cq_);

		status_ = AWAIT_MSG;
		return -1;
	} else if (status_ == AWAIT_MSG) {
		GRPCService* grpc_service = dynamic_cast<GRPCService*>(service_); 
		reply_.set_uuid(grpc_service->GetUUID());
		status_ = FINISH;
		responder_.Finish(reply_, ret, this);
	} else {
		GPR_ASSERT(status_ == FINISH);
		delete this;
	}
	return 0;
}

int AddLBVIPCall::Proceed()
{
	dp_request request = {0};
	dp_reply reply = {0};
	grpc::Status ret = grpc::Status::OK;
	uint8_t buf_bin[16];
	char buf_str[INET6_ADDRSTRLEN];

	if (status_ == REQUEST) {
		new AddLBVIPCall(service_, cq_);
		dp_fill_head(&request.com_head, call_type_, 0, 1);
		if (request_.lbvipip().ipversion() == dpdkonmetal::IPVersion::IPv4) {
			request.add_vip.ip_type = RTE_ETHER_TYPE_IPV4;
			inet_aton(request_.lbvipip().address().c_str(),
					  (in_addr*)&request.add_lb_vip.vip.vip_addr);
			inet_aton(request_.lbbackendip().address().c_str(),
					  (in_addr*)&request.add_lb_vip.back.back_addr);
		}
		request.add_lb_vip.vni = request_.vni();
		dp_send_to_worker(&request);
		status_ = AWAIT_MSG;
		return -1;
	} else if (status_ == AWAIT_MSG) {
		dp_fill_head(&reply.com_head, call_type_, 0, 1);
		if (dp_recv_from_worker(&reply))
			return -1;
		status_ = FINISH;
		GRPCService* grpc_service = dynamic_cast<GRPCService*>(service_); 
		grpc_service->CalculateUnderlayRoute(request_.vni(), buf_bin, sizeof(buf_bin));
		inet_ntop(AF_INET6, buf_bin, buf_str, INET6_ADDRSTRLEN);
		reply_.set_underlay_route(buf_str);
		reply_.set_error(reply.com_head.err_code);
		responder_.Finish(reply_, ret, this);
	} else {
		GPR_ASSERT(status_ == FINISH);
		delete this;
	}
	return 0;
}

int DelLBVIPCall::Proceed()
{
	dp_request request = {0};
	dp_reply reply = {0};
	grpc::Status ret = grpc::Status::OK;

	if (status_ == REQUEST) {
		new DelLBVIPCall(service_, cq_);
		dp_fill_head(&request.com_head, call_type_, 0, 1);
		if (request_.lbvipip().ipversion() == dpdkonmetal::IPVersion::IPv4) {
			request.add_vip.ip_type = RTE_ETHER_TYPE_IPV4;
			inet_aton(request_.lbvipip().address().c_str(),
					  (in_addr*)&request.add_lb_vip.vip.vip_addr);
			inet_aton(request_.lbbackendip().address().c_str(),
					  (in_addr*)&request.add_lb_vip.back.back_addr);
		}
		request.add_lb_vip.vni = request_.vni();
		dp_send_to_worker(&request);
		status_ = AWAIT_MSG;
		return -1;
	} else if (status_ == AWAIT_MSG) {
		dp_fill_head(&reply.com_head, call_type_, 0, 1);
		if (dp_recv_from_worker(&reply))
			return -1;
		status_ = FINISH;
		reply_.set_error(reply.com_head.err_code);
		responder_.Finish(reply_, ret, this);
	} else {
		GPR_ASSERT(status_ == FINISH);
		delete this;
	}
	return 0;
}

int GetLBVIPBackendsCall::Proceed()
{
	dp_request request = {0};
	struct rte_mbuf *mbuf = NULL;
	struct dp_reply *reply;
	struct in_addr addr;
	uint32_t *rp_back_ip;
	LBIP *back_ip;
	grpc::Status ret = grpc::Status::OK;
	int i;

	if (status_ == REQUEST) {
		new GetLBVIPBackendsCall(service_, cq_);
		dp_fill_head(&request.com_head, call_type_, 0, 1);
		if (request_.lbvipip().ipversion() == dpdkonmetal::IPVersion::IPv4) {
			request.add_vip.ip_type = RTE_ETHER_TYPE_IPV4;
			inet_aton(request_.lbvipip().address().c_str(),
					  (in_addr*)&request.add_lb_vip.vip.vip_addr);
		}
		request.add_lb_vip.vni = request_.vni();
		dp_send_to_worker(&request);
		status_ = AWAIT_MSG;
		return -1;
	} else if (status_ == AWAIT_MSG) {
		if (dp_recv_from_worker_with_mbuf(&mbuf))
			return -1;
		reply = rte_pktmbuf_mtod(mbuf, dp_reply*);
		for (i = 0; i < reply->com_head.msg_count; i++) {
			back_ip = reply_.add_backends();
			rp_back_ip = &((&reply->back_ip)[i]);
			addr.s_addr = htonl(*rp_back_ip);
			back_ip->set_address(inet_ntoa(addr));
			back_ip->set_ipversion(dpdkonmetal::IPVersion::IPv4);
		}
		rte_pktmbuf_free(mbuf);
		status_ = FINISH;
		responder_.Finish(reply_, ret, this);
	} else {
		GPR_ASSERT(status_ == FINISH);
		delete this;
	}
	return 0;
}

int AddPfxCall::Proceed()
{
	dp_request request = {0};
	dp_reply reply = {0};
	grpc::Status ret = grpc::Status::OK;
	uint8_t buf_bin[16];
	char buf_str[INET6_ADDRSTRLEN];

	if (status_ == REQUEST) {
		new AddPfxCall(service_, cq_);
		dp_fill_head(&request.com_head, call_type_, 0, 1);
		snprintf(request.add_pfx.machine_id, VM_MACHINE_ID_STR_LEN,
				 "%s", request_.machine_id().machineid().c_str());
		if (request_.prefix().ipversion() == dpdkonmetal::IPVersion::IPv4) {
			request.add_pfx.pfx_ip_type = RTE_ETHER_TYPE_IPV4;
			inet_aton(request_.prefix().address().c_str(),
					  (in_addr*)&request.add_pfx.pfx_ip.pfx_addr);
		}
		request.add_pfx.pfx_length = request_.prefix().prefixlength();
		dp_send_to_worker(&request);
		status_ = AWAIT_MSG;
		return -1;
	} else if (status_ == AWAIT_MSG) {
		dp_fill_head(&reply.com_head, call_type_, 0, 1);
		if (dp_recv_from_worker(&reply))
			return -1;
		status_ = FINISH;
		GRPCService* grpc_service = dynamic_cast<GRPCService*>(service_); 
		grpc_service->CalculateUnderlayRoute(reply.vni, buf_bin, sizeof(buf_bin));
		inet_ntop(AF_INET6, buf_bin, buf_str, INET6_ADDRSTRLEN);
		reply_.set_underlay_route(buf_str);
		reply_.set_error(reply.com_head.err_code);
		responder_.Finish(reply_, ret, this);
	} else {
		GPR_ASSERT(status_ == FINISH);
		delete this;
	}
	return 0;
}

int DelPfxCall::Proceed()
{
	dp_request request = {0};
	dp_reply reply= {0};
	grpc::Status ret = grpc::Status::OK;

	if (status_ == REQUEST) {
		new DelPfxCall(service_, cq_);
		dp_fill_head(&request.com_head, call_type_, 0, 1);
		snprintf(request.add_pfx.machine_id, VM_MACHINE_ID_STR_LEN,
				 "%s", request_.machine_id().machineid().c_str());
		if (request_.prefix().ipversion() == dpdkonmetal::IPVersion::IPv4) {
			request.add_pfx.pfx_ip_type = RTE_ETHER_TYPE_IPV4;
			inet_aton(request_.prefix().address().c_str(),
					  (in_addr*)&request.add_pfx.pfx_ip.pfx_addr);
		}
		request.add_pfx.pfx_length = request_.prefix().prefixlength();
		dp_send_to_worker(&request);
		status_ = AWAIT_MSG;
		return -1;
	} else if (status_ == AWAIT_MSG) {
		if (dp_recv_from_worker(&reply))
			return -1;
		reply_.set_error(reply.com_head.err_code);
		status_ = FINISH;
		responder_.Finish(reply_, ret, this);
	} else {
		GPR_ASSERT(status_ == FINISH);
		delete this;
	}
	return 0;
}

int ListPfxCall::Proceed()
{
	dp_request request = {0};
	struct rte_mbuf *mbuf = NULL;
	struct dp_reply *reply;
	struct in_addr addr;
	dp_route *rp_route;
	Prefix *pfx;
	grpc::Status ret = grpc::Status::OK;
	int i;

	if (status_ == REQUEST) {
		new ListPfxCall(service_, cq_);
		dp_fill_head(&request.com_head, call_type_, 0, 1);
		snprintf(request.get_pfx.machine_id, VM_MACHINE_ID_STR_LEN,
				 "%s", request_.machineid().c_str());
		dp_send_to_worker(&request);
		status_ = AWAIT_MSG;
		return -1;
	} else if (status_ == AWAIT_MSG) {
		if (dp_recv_from_worker_with_mbuf(&mbuf))
			return -1;
		reply = rte_pktmbuf_mtod(mbuf, dp_reply*);
		for (i = 0; i < reply->com_head.msg_count; i++) {
			pfx = reply_.add_prefixes();
			rp_route = &((&reply->route)[i]);
			if (rp_route->pfx_ip_type == RTE_ETHER_TYPE_IPV4) {
				addr.s_addr = htonl(rp_route->pfx_ip.addr);
				pfx->set_address(inet_ntoa(addr));
				pfx->set_ipversion(dpdkonmetal::IPVersion::IPv4);
				pfx->set_prefixlength(rp_route->pfx_length);
			}
		}
		rte_pktmbuf_free(mbuf);
		status_ = FINISH;
		responder_.Finish(reply_, ret, this);
	} else {
		GPR_ASSERT(status_ == FINISH);
		delete this;
	}
	return 0;
}

int AddVIPCall::Proceed()
{
	dp_request request = {0};
	dp_reply reply = {0};
	grpc::Status ret = grpc::Status::OK;
	uint8_t buf_bin[16];
	char buf_str[INET6_ADDRSTRLEN];

	if (status_ == REQUEST) {
		new AddVIPCall(service_, cq_);
		dp_fill_head(&request.com_head, call_type_, 0, 1);
		snprintf(request.add_vip.machine_id, VM_MACHINE_ID_STR_LEN,
				 "%s", request_.machineid().c_str());
		if (request_.machinevipip().ipversion() == dpdkonmetal::IPVersion::IPv4) {
			request.add_vip.ip_type = RTE_ETHER_TYPE_IPV4;
			inet_aton(request_.machinevipip().address().c_str(),
					  (in_addr*)&request.add_vip.vip.vip_addr);
		}
		dp_send_to_worker(&request);
		status_ = AWAIT_MSG;
		return -1;
	} else if (status_ == AWAIT_MSG) {
		dp_fill_head(&reply.com_head, call_type_, 0, 1);
		if (dp_recv_from_worker(&reply))
			return -1;
		status_ = FINISH;
		GRPCService* grpc_service = dynamic_cast<GRPCService*>(service_); 
		grpc_service->CalculateUnderlayRoute(reply.vni, buf_bin, sizeof(buf_bin));
		inet_ntop(AF_INET6, buf_bin, buf_str, INET6_ADDRSTRLEN);
		reply_.set_underlay_route(buf_str);
		reply_.set_error(reply.com_head.err_code);
		responder_.Finish(reply_, ret, this);
	} else {
		GPR_ASSERT(status_ == FINISH);
		delete this;
	}
	return 0;
}

int DelVIPCall::Proceed()
{
	dp_request request = {0};
	dp_reply reply = {0};
	grpc::Status ret = grpc::Status::OK;

	if (status_ == REQUEST) {
		new DelVIPCall(service_, cq_);
		dp_fill_head(&request.com_head, call_type_, 0, 1);
		snprintf(request.del_vip.machine_id, VM_MACHINE_ID_STR_LEN,
				 "%s", request_.machineid().c_str());
		dp_send_to_worker(&request);
		status_ = AWAIT_MSG;
		return -1;
	} else if (status_ == AWAIT_MSG) {
		dp_fill_head(&reply.com_head, call_type_, 0, 1);
		if (dp_recv_from_worker(&reply))
			return -1;
		status_ = FINISH;
		reply_.set_error(reply.com_head.err_code);
		responder_.Finish(reply_, ret, this);
	} else {
		GPR_ASSERT(status_ == FINISH);
		delete this;
	}
	return 0;
}

int GetVIPCall::Proceed()
{
	dp_request request = {0};
	dp_reply reply = {0};
	Status *err_status = new Status();
	struct in_addr addr;
	grpc::Status ret = grpc::Status::OK;

	if (status_ == REQUEST) {
		new GetVIPCall(service_, cq_);
		dp_fill_head(&request.com_head, call_type_, 0, 1);
		snprintf(request.get_vip.machine_id, VM_MACHINE_ID_STR_LEN,
				 "%s", request_.machineid().c_str());
		dp_send_to_worker(&request);
		status_ = AWAIT_MSG;
		return -1;
	} else if (status_ == AWAIT_MSG) {
		dp_fill_head(&reply.com_head, call_type_, 0, 1);
		if (dp_recv_from_worker(&reply))
			return -1;
		reply_.set_ipversion(dpdkonmetal::IPVersion::IPv4);
		addr.s_addr = reply.get_vip.vip.vip_addr;
		reply_.set_address(inet_ntoa(addr));
		status_ = FINISH;
		err_status->set_error(reply.com_head.err_code);
		reply_.set_allocated_status(err_status);
		responder_.Finish(reply_, ret, this);
	} else {
		GPR_ASSERT(status_ == FINISH);
		delete this;
	}
	return 0;
}

int AddMachineCall::Proceed()
{
	dp_request request = {0};
	dp_reply reply = {0};
	VirtualFunction *vf = new VirtualFunction();
	ExtStatus *err_status = new ExtStatus();
	grpc::Status ret = grpc::Status::OK;
	uint8_t buf_bin[16];
	char buf_str[INET6_ADDRSTRLEN];

	if (status_ == REQUEST) {
		new AddMachineCall(service_, cq_);
		dp_fill_head(&request.com_head, call_type_, 0, 1);
		err_status->set_error(EXIT_SUCCESS);
		request.add_machine.vni = request_.vni();
		inet_aton(request_.ipv4config().primaryaddress().c_str(),
				  (in_addr*)&request.add_machine.ip4_addr);
		inet_aton(request_.ipv4config().pxeconfig().nextserver().c_str(),
				  (in_addr*)&request.add_machine.ip4_pxe_addr);
		snprintf(request.add_machine.pxe_str, VM_MACHINE_PXE_STR_LEN, "%s",
				 request_.ipv4config().pxeconfig().bootfilename().c_str());
		snprintf(request.add_machine.name, sizeof(request.add_machine.name), "%s",
				 request_.devicename().c_str());
		uint8_t ret = inet_pton(AF_INET6, request_.ipv6config().primaryaddress().c_str(),
								request.add_machine.ip6_addr6);
		if(ret < 0)
			err_status->set_error(DP_ERROR_VM_ADD_IPV6_FORMAT);

		snprintf(request.add_machine.machine_id, VM_MACHINE_ID_STR_LEN, "%s",
				 request_.machineid().c_str());
		if (!err_status->error())
			dp_send_to_worker(&request);
		status_ = AWAIT_MSG;
		return -1;
	} else if (status_ == AWAIT_MSG) {
		if (!err_status->error()) {
			dp_fill_head(&reply.com_head, call_type_, 0, 1);
			if (dp_recv_from_worker(&reply))
				return -1;
			vf->set_name(reply.vf_pci.name);
			vf->set_bus(reply.vf_pci.bus);
			vf->set_domain(reply.vf_pci.domain);
			vf->set_slot(reply.vf_pci.slot);
			vf->set_function(reply.vf_pci.function);
			reply_.set_allocated_vf(vf);
			err_status->set_error(reply.com_head.err_code);
		}
		GRPCService* grpc_service = dynamic_cast<GRPCService*>(service_); 
		grpc_service->CalculateUnderlayRoute(request_.vni(), buf_bin, sizeof(buf_bin));
		inet_ntop(AF_INET6, buf_bin, buf_str, INET6_ADDRSTRLEN);
		err_status->set_underlay_route(buf_str);
		reply_.set_allocated_status(err_status);
		status_ = FINISH;
		responder_.Finish(reply_, ret, this);
	} else {
		GPR_ASSERT(status_ == FINISH);
		delete this;
	}
	return 0;
}

int DelMachineCall::Proceed()
{
	dp_request request = {0};
	dp_reply reply= {0};
	grpc::Status ret = grpc::Status::OK;

	if (status_ == REQUEST) {
		new DelMachineCall(service_, cq_);
		dp_fill_head(&request.com_head, call_type_, 0, 1);
		snprintf(request.del_machine.machine_id, VM_MACHINE_ID_STR_LEN,
				 "%s", request_.machineid().c_str());
		dp_send_to_worker(&request);
		status_ = AWAIT_MSG;
		return -1;
	} else if (status_ == AWAIT_MSG) {
		dp_fill_head(&reply.com_head, call_type_, 0, 1);
		if (dp_recv_from_worker(&reply))
			return -1;
		reply_.set_error(reply.com_head.err_code);
		status_ = FINISH;
		responder_.Finish(reply_, ret, this);
	} else {
		GPR_ASSERT(status_ == FINISH);
		delete this;
	}
	return 0;
}

int AddRouteCall::Proceed()
{
	dp_request request = {0};
	dp_reply reply= {0};
	grpc::Status ret = grpc::Status::OK;

	if (status_ == REQUEST) {
		new AddRouteCall(service_, cq_);
		dp_fill_head(&request.com_head, call_type_, 0, 1);
		request.route.vni = request_.vni().vni();
		request.route.trgt_hop_ip_type = RTE_ETHER_TYPE_IPV6;
		request.route.trgt_vni = request_.route().nexthopvni();
		inet_pton(AF_INET6, request_.route().nexthopaddress().c_str(),
				  request.route.trgt_ip.addr6);
		request.route.pfx_length = request_.route().prefix().prefixlength();
		if(request_.route().prefix().ipversion() == dpdkonmetal::IPVersion::IPv4) {
			request.route.pfx_ip_type = RTE_ETHER_TYPE_IPV4;
			inet_aton(request_.route().prefix().address().c_str(),
					  (in_addr*)&request.route.pfx_ip.addr);
		} else {
			request.route.pfx_ip_type = RTE_ETHER_TYPE_IPV6;
			inet_pton(AF_INET6, request_.route().prefix().address().c_str(),
					  request.route.pfx_ip.addr6);
		}
		dp_send_to_worker(&request);
		status_ = AWAIT_MSG;
		return -1;
	} else if (status_ == AWAIT_MSG) {
		dp_fill_head(&reply.com_head, call_type_, 0, 1);
		if (dp_recv_from_worker(&reply))
			return -1;
		reply_.set_error(reply.com_head.err_code);
		status_ = FINISH;
		responder_.Finish(reply_, ret, this);
	} else {
		GPR_ASSERT(status_ == FINISH);
		delete this;
	}
	return 0;
}

int DelRouteCall::Proceed()
{
	dp_request request = {0};
	dp_reply reply= {0};
	grpc::Status ret = grpc::Status::OK;

	if (status_ == REQUEST) {
		new DelRouteCall(service_, cq_);
		dp_fill_head(&request.com_head, call_type_, 0, 1);
		request.route.vni = request_.vni().vni();
		request.route.trgt_hop_ip_type = RTE_ETHER_TYPE_IPV6;
		request.route.trgt_vni = request_.route().nexthopvni();
		inet_pton(AF_INET6, request_.route().nexthopaddress().c_str(),
				  request.route.trgt_ip.addr6);
		request.route.pfx_length = request_.route().prefix().prefixlength();
		if(request_.route().prefix().ipversion() == dpdkonmetal::IPVersion::IPv4) {
			request.route.pfx_ip_type = RTE_ETHER_TYPE_IPV4;
			inet_aton(request_.route().prefix().address().c_str(),
					  (in_addr*)&request.route.pfx_ip.addr);
		} else {
			request.route.pfx_ip_type = RTE_ETHER_TYPE_IPV6;
			inet_pton(AF_INET6, request_.route().prefix().address().c_str(),
					  request.route.pfx_ip.addr6);
		}
		dp_send_to_worker(&request);
		status_ = AWAIT_MSG;
		return -1;
	} else if (status_ == AWAIT_MSG) {
		if (dp_recv_from_worker(&reply))
			return -1;
		reply_.set_error(reply.com_head.err_code);
		status_ = FINISH;
		responder_.Finish(reply_, ret, this);
	} else {
		GPR_ASSERT(status_ == FINISH);
		delete this;
	}
	return 0;
}

int ListRoutesCall::Proceed()
{
	dp_request request = {0};
	struct rte_mbuf *mbuf = NULL;
	struct dp_reply *reply;
	struct in_addr addr;
	dp_route *rp_route;
	Prefix *pfx;
	Route *route;
	grpc::Status ret = grpc::Status::OK;
	int i;
	char buf[INET6_ADDRSTRLEN];

	if (status_ == REQUEST) {
		new ListRoutesCall(service_, cq_);
		dp_fill_head(&request.com_head, call_type_, 0, 1);
		request.route.vni = request_.vni();
		dp_send_to_worker(&request);
		status_ = AWAIT_MSG;
		return -1;
	} else if (status_ == AWAIT_MSG) {
		if (dp_recv_from_worker_with_mbuf(&mbuf))
			return -1;
		reply = rte_pktmbuf_mtod(mbuf, dp_reply*);
		for (i = 0; i < reply->com_head.msg_count; i++) {
			route = reply_.add_routes();
			rp_route = &((&reply->route)[i]);
			
			if (rp_route->trgt_hop_ip_type == RTE_ETHER_TYPE_IPV6)
				route->set_ipversion(dpdkonmetal::IPVersion::IPv6);
			else
				route->set_ipversion(dpdkonmetal::IPVersion::IPv4);

			if (rp_route->pfx_ip_type == RTE_ETHER_TYPE_IPV4) {
				addr.s_addr = htonl(rp_route->pfx_ip.addr);
				pfx = new Prefix();
				pfx->set_address(inet_ntoa(addr));
				pfx->set_ipversion(dpdkonmetal::IPVersion::IPv4);
				pfx->set_prefixlength(rp_route->pfx_length);
				route->set_allocated_prefix(pfx);
			}
			route->set_nexthopvni(rp_route->trgt_vni);
			inet_ntop(AF_INET6, rp_route->trgt_ip.addr6, buf, INET6_ADDRSTRLEN);
			route->set_nexthopaddress(buf);
		}
		rte_pktmbuf_free(mbuf);
		status_ = FINISH;
		responder_.Finish(reply_, ret, this);
	} else {
		GPR_ASSERT(status_ == FINISH);
		delete this;
	}
	return 0;
}

int ListMachinesCall::Proceed()
{
	dp_request request = {0};
	struct rte_mbuf *mbuf = NULL;
	struct dp_reply *reply;
	Machine *machine;
	struct in_addr addr;
	dp_vm_info *vm_info;
	int i;
	grpc::Status ret = grpc::Status::OK;
	char buf[INET6_ADDRSTRLEN];

	if (status_ == REQUEST) {
		new ListMachinesCall(service_, cq_);
		dp_fill_head(&request.com_head, call_type_, 0, 1);
		dp_send_to_worker(&request);
		status_ = AWAIT_MSG;
		return -1;
	} else if (status_ == AWAIT_MSG) {
		if (dp_recv_from_worker_with_mbuf(&mbuf))
			return -1;
		reply = rte_pktmbuf_mtod(mbuf, dp_reply*);
		for (i = 0; i < reply->com_head.msg_count; i++) {
			machine = reply_.add_machines();
			vm_info = &((&reply->vm_info)[i]);
			addr.s_addr = htonl(vm_info->ip_addr);
			machine->set_primaryipv4address(inet_ntoa(addr));
			inet_ntop(AF_INET6, vm_info->ip6_addr, buf, INET6_ADDRSTRLEN);
			machine->set_primaryipv6address(buf);
			machine->set_machineid((char *)vm_info->machine_id);
			machine->set_vni(vm_info->vni);
		}
		rte_pktmbuf_free(mbuf);
		status_ = FINISH;
		responder_.Finish(reply_, ret, this);
	} else {
		GPR_ASSERT(status_ == FINISH);
		delete this;
	}
	return 0;
}
