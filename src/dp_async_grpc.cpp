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
		//Fill from request_ into request
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
		// Fill into reply_ from reply
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
		// Fill into reply_ from reply
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
