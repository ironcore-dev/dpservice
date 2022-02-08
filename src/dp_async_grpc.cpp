#include "dp_async_grpc.h"
#include "dp_grpc_impl.h"
#include <rte_mbuf.h>

int HelloCall::Proceed()
{
	dp_request request;
	dp_reply reply;
	grpc::Status ret = grpc::Status::OK;

	if (status_ == REQUEST) {
		new HelloCall(service_, cq_);
		dp_fill_head(&request.com_head, call_type_, 0, 1);
		request.hello = 0xdeadbeef;
		printf("GRPC Hello sent %x \n", request.hello);
		dp_send_to_worker(&request);
		status_ = AWAIT_MSG;
		return -1;
	} else if (status_ == AWAIT_MSG) {
		dp_fill_head(&reply.com_head, call_type_, 0, 1);
		if (dp_recv_from_worker(&reply))
			return -1;
		printf("GRPC Hello received %x \n", reply.hello);
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
		printf("GRPC addvip called \n");
		dp_send_to_worker(&request);
		status_ = AWAIT_MSG;
		return -1;
	} else if (status_ == AWAIT_MSG) {
		dp_fill_head(&reply.com_head, call_type_, 0, 1);
		if (dp_recv_from_worker(&reply))
			return -1;
		printf("GRPC addvip reply received \n");
		status_ = FINISH;
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
		printf("GRPC delvip called \n");
		dp_send_to_worker(&request);
		status_ = AWAIT_MSG;
		return -1;
	} else if (status_ == AWAIT_MSG) {
		dp_fill_head(&reply.com_head, call_type_, 0, 1);
		if (dp_recv_from_worker(&reply))
			return -1;
		printf("GRPC delvip reply received \n");
		status_ = FINISH;
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
	struct in_addr addr;
	grpc::Status ret = grpc::Status::OK;

	if (status_ == REQUEST) {
		new GetVIPCall(service_, cq_);
		dp_fill_head(&request.com_head, call_type_, 0, 1);
		snprintf(request.get_vip.machine_id, VM_MACHINE_ID_STR_LEN,
				 "%s", request_.machineid().c_str());
		printf("GRPC getvip called \n");
		dp_send_to_worker(&request);
		status_ = AWAIT_MSG;
		return -1;
	} else if (status_ == AWAIT_MSG) {
		dp_fill_head(&reply.com_head, call_type_, 0, 1);
		if (dp_recv_from_worker(&reply))
			return -1;
		printf("GRPC getvip reply received \n");
		reply_.set_ipversion(dpdkonmetal::IPVersion::IPv4);
		addr.s_addr = reply.get_vip.vip.vip_addr;
		reply_.set_address(inet_ntoa(addr));
		status_ = FINISH;
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
	grpc::Status ret = grpc::Status::OK;

	if (status_ == REQUEST) {
		new AddMachineCall(service_, cq_);
		dp_fill_head(&request.com_head, call_type_, 0, 1);
		request.add_machine.vni = request_.vni();
		inet_aton(request_.ipv4config().primaryaddress().c_str(),
				  (in_addr*)&request.add_machine.ip4_addr);
		uint8_t ret = inet_pton(AF_INET6, request_.ipv6config().primaryaddress().c_str(),
								request.add_machine.ip6_addr6);
		if(ret < 0)
			printf("IPv6 address not in proper format\n");

		snprintf(request.add_machine.machine_id, VM_MACHINE_ID_STR_LEN, "%s",
				 request_.machineid().c_str());
		printf("GRPC addmachine called \n");
		dp_send_to_worker(&request);
		status_ = AWAIT_MSG;
		return -1;
	} else if (status_ == AWAIT_MSG) {
		dp_fill_head(&reply.com_head, call_type_, 0, 1);
		if (dp_recv_from_worker(&reply))
			return -1;
		printf("GRPC addmachine reply received \n");
		vf->set_name(reply.vf_pci.name);
		vf->set_bus(reply.vf_pci.bus);
		vf->set_domain(reply.vf_pci.domain);
		vf->set_slot(reply.vf_pci.slot);
		vf->set_function(reply.vf_pci.function);
		reply_.set_allocated_vf(vf);
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
		printf("GRPC delmachine called \n");
		dp_send_to_worker(&request);
		status_ = AWAIT_MSG;
		return -1;
	} else if (status_ == AWAIT_MSG) {
		dp_fill_head(&reply.com_head, call_type_, 0, 1);
		if (dp_recv_from_worker(&reply))
			return -1;
		printf("GRPC delmachine reply received \n");
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
		printf("GRPC addroute called \n");
		dp_send_to_worker(&request);
		status_ = AWAIT_MSG;
		return -1;
	} else if (status_ == AWAIT_MSG) {
		dp_fill_head(&reply.com_head, call_type_, 0, 1);
		if (dp_recv_from_worker(&reply))
			return -1;
		printf("GRPC addroute reply received \n");
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
		printf("GRPC delroute called \n");
		dp_send_to_worker(&request);
		status_ = AWAIT_MSG;
		return -1;
	} else if (status_ == AWAIT_MSG) {
		if (dp_recv_from_worker(&reply))
			return -1;
		printf("GRPC delroute reply received \n");
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
		printf("GRPC listmachines called \n");
		dp_send_to_worker(&request);
		status_ = AWAIT_MSG;
		return -1;
	} else if (status_ == AWAIT_MSG) {
		if (dp_recv_from_worker_with_mbuf(&mbuf))
			return -1;
		printf("GRPC listmachines reply received \n");
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
