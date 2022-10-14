#include "grpc/dp_async_grpc.h"
#include "grpc/dp_grpc_service.h"
#include "grpc/dp_grpc_impl.h"
#include <arpa/inet.h>
#include <rte_mbuf.h>
#include <dp_error.h>
#include <dp_util.h>
#include <dp_lpm.h>
#include <rte_ether.h>

int BaseCall::InitCheck()
{
	GRPCService* grpc_service = dynamic_cast<GRPCService*>(service_);

	if (!grpc_service->IsInitialized()) {
		status_ = INITCHECK;
		ret = grpc::Status(grpc::StatusCode::ABORTED, "not initialized");
	} else {
		status_ = AWAIT_MSG;
	}

	return status_;
}

int InitializedCall::Proceed()
{
	if (status_ == REQUEST) {
		new InitializedCall(service_, cq_);
		InitCheck();
		return -1;
	} else if (status_ == INITCHECK) {
		responder_.Finish(reply_, ret, this);
		status_ = FINISH;
	} else if (status_ == AWAIT_MSG) {
		GRPCService* grpc_service = dynamic_cast<GRPCService*>(service_);
		reply_.set_uuid(grpc_service->GetUUID());
		responder_.Finish(reply_, ret, this);
		status_ = FINISH;
	} else {
		GPR_ASSERT(status_ == FINISH);
		delete this;
	}
	return 0;
}

int InitCall::Proceed()
{
	if (status_ == REQUEST) {
		new InitCall(service_, cq_);
		status_ = AWAIT_MSG;
		DPS_LOG(INFO, DPSERVICE, "GRPC init called \n");
		return -1;
	} else if (status_ == AWAIT_MSG) {
		GRPCService* grpc_service = dynamic_cast<GRPCService*>(service_);
		grpc_service->SetInitStatus(true);
		status_ = FINISH;
		responder_.Finish(reply_, ret, this);
	} else {
		GPR_ASSERT(status_ == FINISH);
		delete this;
	}
	return 0;
}

int CreateLBCall::Proceed()
{
	dp_request request = {0};
	dp_reply reply = {0};
	uint16_t i, size;
	Status *err_status;
	uint8_t buf_bin[16];
	char buf_str[INET6_ADDRSTRLEN];

	if (status_ == REQUEST) {
		new CreateLBCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		DPS_LOG(INFO, DPSERVICE, "GRPC create LoadBalancer called for id: %s\n", request_.loadbalancerid().c_str());
		dp_fill_head(&request.com_head, call_type_, 0, 1);
		snprintf(request.add_lb.lb_id, DP_LB_ID_SIZE, "%s",
				 request_.loadbalancerid().c_str());
		request.add_lb.vni = request_.vni();
		if (request_.lbvipip().ipversion() == dpdkonmetal::IPVersion::IPv4) {
			request.add_lb.ip_type = RTE_ETHER_TYPE_IPV4;
			inet_aton(request_.lbvipip().address().c_str(),
					  (in_addr*)&request.add_lb_vip.back.back_addr);
			size = (request_.lbports_size() >= DP_LB_PORT_SIZE) ? DP_LB_PORT_SIZE : request_.lbports_size();
			for (i = 0; i < size; i++) {
				request.add_lb.lbports[i].port = request_.lbports(i).port();
				if (request_.lbports(i).protocol() == TCP)
					request.add_lb.lbports[i].protocol = DP_IP_PROTO_TCP;
				if (request_.lbports(i).protocol() == UDP)
					request.add_lb.lbports[i].protocol = DP_IP_PROTO_UDP;
			}
		} else {
			request.add_lb.ip_type = RTE_ETHER_TYPE_IPV4;
		}
		dp_send_to_worker(&request);
		status_ = AWAIT_MSG;
		return -1;
	} else if (status_ == INITCHECK) {
		responder_.Finish(reply_, ret, this);
		status_ = FINISH;
	} else if (status_ == AWAIT_MSG) {
		dp_fill_head(&reply.com_head, call_type_, 0, 1);
		if (dp_recv_from_worker(&reply))
			return -1;
		status_ = FINISH;
		GRPCService* grpc_service = dynamic_cast<GRPCService*>(service_); 
		grpc_service->CalculateUnderlayRoute(reply.vni, buf_bin, sizeof(buf_bin));
		inet_ntop(AF_INET6, buf_bin, buf_str, INET6_ADDRSTRLEN);
		reply_.set_underlayroute(buf_str);
		err_status = new Status();
		err_status->set_error(reply.com_head.err_code);
		reply_.set_allocated_status(err_status);
		responder_.Finish(reply_, ret, this);
	} else {
		GPR_ASSERT(status_ == FINISH);
		delete this;
	}
	return 0;
}

int DelLBCall::Proceed()
{
	dp_request request = {0};
	dp_reply reply = {0};

	if (status_ == REQUEST) {
		new DelLBCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		DPS_LOG(INFO, DPSERVICE, "GRPC delete LoadBalancer called for id: %s\n", request_.loadbalancerid().c_str());
		dp_fill_head(&request.com_head, call_type_, 0, 1);
		snprintf(request.del_lb.lb_id, DP_LB_ID_SIZE, "%s",
				 request_.loadbalancerid().c_str());
		dp_send_to_worker(&request);
		status_ = AWAIT_MSG;
		return -1;
	} else if (status_ == INITCHECK) {
		responder_.Finish(reply_, ret, this);
		status_ = FINISH;
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

int GetLBCall::Proceed()
{
	dp_request request = {0};
	dp_reply reply = {0};
	struct in_addr addr;
	Status *err_status;
	LBPort *lb_port;
	LBIP *lb_ip;
	int i;

	if (status_ == REQUEST) {
		new GetLBCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		DPS_LOG(INFO, DPSERVICE, "GRPC get LoadBalancer called for id: %s\n", request_.loadbalancerid().c_str());
		dp_fill_head(&request.com_head, call_type_, 0, 1);
		snprintf(request.add_lb.lb_id, DP_LB_ID_SIZE, "%s",
				 request_.loadbalancerid().c_str());
		dp_send_to_worker(&request);
		status_ = AWAIT_MSG;
		return -1;
	} else if (status_ == INITCHECK) {
		responder_.Finish(reply_, ret, this);
		status_ = FINISH;
	} else if (status_ == AWAIT_MSG) {
		dp_fill_head(&reply.com_head, call_type_, 0, 1);
		if (dp_recv_from_worker(&reply))
			return -1;
		status_ = FINISH;
		reply_.set_vni(reply.get_lb.vni);
		lb_ip = new LBIP();
		addr.s_addr = reply.get_lb.vip.vip_addr;
		lb_ip->set_address(inet_ntoa(addr));
		if (reply.get_lb.ip_type == RTE_ETHER_TYPE_IPV4)
			lb_ip->set_ipversion(IPv4);
		else
			lb_ip->set_ipversion(IPv6);
		reply_.set_allocated_lbvipip(lb_ip);
		for (i = 0; i < DP_LB_PORT_SIZE; i++) {
			if (reply.get_lb.lbports[i].port == 0)
				continue;
			lb_port = reply_.add_lbports();
			lb_port->set_port(reply.get_lb.lbports[i].port);
			if (reply.get_lb.lbports[i].protocol == DP_IP_PROTO_TCP)
				lb_port->set_protocol(TCP);
			if (reply.get_lb.lbports[i].protocol == DP_IP_PROTO_UDP)
				lb_port->set_protocol(UDP);
		}
		err_status = new Status();
		err_status->set_error(reply.com_head.err_code);
		reply_.set_allocated_status(err_status);
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

	if (status_ == REQUEST) {
		new AddLBVIPCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		DPS_LOG(INFO, DPSERVICE, "GRPC add LoadBalancer target called for id: %s\n", request_.loadbalancerid().c_str());
		dp_fill_head(&request.com_head, call_type_, 0, 1);
		snprintf(request.add_lb_vip.lb_id, DP_LB_ID_SIZE, "%s",
				 request_.loadbalancerid().c_str());
		if (request_.targetip().ipversion() == dpdkonmetal::IPVersion::IPv6) {
			request.add_lb_vip.ip_type = RTE_ETHER_TYPE_IPV6;
			inet_pton(AF_INET6, request_.targetip().address().c_str(),
					  request.add_lb_vip.back.back_addr6);
		} else {
			request.add_lb_vip.ip_type = RTE_ETHER_TYPE_IPV4;
		}
		dp_send_to_worker(&request);
		status_ = AWAIT_MSG;
		return -1;
	} else if (status_ == INITCHECK) {
		responder_.Finish(reply_, ret, this);
		status_ = FINISH;
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

int DelLBVIPCall::Proceed()
{
	dp_request request = {0};
	dp_reply reply = {0};

	if (status_ == REQUEST) {
		new DelLBVIPCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		DPS_LOG(INFO, DPSERVICE, "GRPC delete LoadBalancer target called for id: %s\n", request_.loadbalancerid().c_str());
		dp_fill_head(&request.com_head, call_type_, 0, 1);
		snprintf(request.del_lb_vip.lb_id, DP_LB_ID_SIZE, "%s",
				 request_.loadbalancerid().c_str());
		if (request_.targetip().ipversion() == dpdkonmetal::IPVersion::IPv6) {
			request.del_lb_vip.ip_type = RTE_ETHER_TYPE_IPV6;
			inet_pton(AF_INET6, request_.targetip().address().c_str(),
					  request.del_lb_vip.back.back_addr6);
		} else {
			request.del_lb_vip.ip_type = RTE_ETHER_TYPE_IPV4;
		}
		dp_send_to_worker(&request);
		status_ = AWAIT_MSG;
		return -1;
	} else if (status_ == INITCHECK) {
		responder_.Finish(reply_, ret, this);
		status_ = FINISH;
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
	uint8_t *rp_back_ip;
	LBIP *back_ip;
	char buf_str[INET6_ADDRSTRLEN];
	int i;

	if (status_ == REQUEST) {
		new GetLBVIPBackendsCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		DPS_LOG(INFO, DPSERVICE, "GRPC list LoadBalancer targets called for id: %s\n", request_.loadbalancerid().c_str());
		dp_fill_head(&request.com_head, call_type_, 0, 1);
		snprintf(request.qry_lb_vip.lb_id, DP_LB_ID_SIZE, "%s",
				 request_.loadbalancerid().c_str());
		dp_send_to_worker(&request);
		status_ = AWAIT_MSG;
		return -1;
	} else if (status_ == INITCHECK) {
		responder_.Finish(reply_, ret, this);
		status_ = FINISH;
	} else if (status_ == AWAIT_MSG) {
		if (dp_recv_from_worker_with_mbuf(&mbuf))
			return -1;
		reply = rte_pktmbuf_mtod(mbuf, dp_reply*);
		rp_back_ip = &reply->back_ip.b_ip.addr6[0];
		for (i = 0; i < reply->com_head.msg_count; i++) {
			back_ip = reply_.add_targetips();
			inet_ntop(AF_INET6, rp_back_ip, buf_str, INET6_ADDRSTRLEN);
			back_ip->set_address(buf_str);
			back_ip->set_ipversion(dpdkonmetal::IPVersion::IPv6);
			rp_back_ip += sizeof(reply->back_ip.b_ip.addr6);
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
	Status *err_status = new Status();
	uint8_t buf_bin[16];
	char buf_str[INET6_ADDRSTRLEN];

	if (status_ == REQUEST) {
		new AddPfxCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		DPS_LOG(INFO, DPSERVICE, "GRPC add AliasPrefix called for id: %s\n", request_.interfaceid().interfaceid().c_str());
		dp_fill_head(&request.com_head, call_type_, 0, 1);
		snprintf(request.add_pfx.machine_id, VM_MACHINE_ID_STR_LEN,
				 "%s", request_.interfaceid().interfaceid().c_str());
		if (request_.prefix().ipversion() == dpdkonmetal::IPVersion::IPv4) {
			request.add_pfx.pfx_ip_type = RTE_ETHER_TYPE_IPV4;
			inet_aton(request_.prefix().address().c_str(),
					  (in_addr*)&request.add_pfx.pfx_ip.pfx_addr);
		}
		request.add_pfx.pfx_length = request_.prefix().prefixlength();
		if (request_.prefix().loadbalancerenabled())
			request.add_pfx.pfx_lb_enabled = 1;
		GRPCService* grpc_service = dynamic_cast<GRPCService*>(service_);
		grpc_service->CalculateUnderlayRoute(0, buf_bin, sizeof(buf_bin));
		memcpy(request.add_pfx.pfx_ul_addr6, buf_bin, sizeof(request.add_pfx.pfx_ul_addr6));
		dp_send_to_worker(&request);
		status_ = AWAIT_MSG;
		return -1;
	} else if (status_ == INITCHECK) {
		responder_.Finish(reply_, ret, this);
		status_ = FINISH;
	} else if (status_ == AWAIT_MSG) {
		dp_fill_head(&reply.com_head, call_type_, 0, 1);
		if (dp_recv_from_worker(&reply))
			return -1;
		status_ = FINISH;
		inet_ntop(AF_INET6, buf_bin, buf_str, INET6_ADDRSTRLEN);
		reply_.set_underlayroute(buf_str);
		err_status->set_error(reply.com_head.err_code);
		reply_.set_allocated_status(err_status);
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

	if (status_ == REQUEST) {
		new DelPfxCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		DPS_LOG(INFO, DPSERVICE, "GRPC delete AliasPrefix called for id: %s\n", request_.interfaceid().interfaceid().c_str());
		dp_fill_head(&request.com_head, call_type_, 0, 1);
		snprintf(request.add_pfx.machine_id, VM_MACHINE_ID_STR_LEN,
				 "%s", request_.interfaceid().interfaceid().c_str());
		if (request_.prefix().ipversion() == dpdkonmetal::IPVersion::IPv4) {
			request.add_pfx.pfx_ip_type = RTE_ETHER_TYPE_IPV4;
			inet_aton(request_.prefix().address().c_str(),
					  (in_addr*)&request.add_pfx.pfx_ip.pfx_addr);
		}
		request.add_pfx.pfx_length = request_.prefix().prefixlength();
		dp_send_to_worker(&request);
		status_ = AWAIT_MSG;
		return -1;
	} else if (status_ == INITCHECK) {
		responder_.Finish(reply_, ret, this);
		status_ = FINISH;
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
	int i;

	if (status_ == REQUEST) {
		new ListPfxCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		DPS_LOG(INFO, DPSERVICE, "GRPC list AliasPrefix(es) called for id: %s\n", request_.interfaceid().c_str());
		dp_fill_head(&request.com_head, call_type_, 0, 1);
		snprintf(request.get_pfx.machine_id, VM_MACHINE_ID_STR_LEN,
				 "%s", request_.interfaceid().c_str());
		dp_send_to_worker(&request);
		status_ = AWAIT_MSG;
		return -1;
	} else if (status_ == INITCHECK) {
		responder_.Finish(reply_, ret, this);
		status_ = FINISH;
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
	Status *err_status = new Status();
	uint8_t buf_bin[16];
	char buf_str[INET6_ADDRSTRLEN];

	if (status_ == REQUEST) {
		new AddVIPCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		DPS_LOG(INFO, DPSERVICE, "GRPC add VIP called for id: %s\n", request_.interfaceid().c_str());
		dp_fill_head(&request.com_head, call_type_, 0, 1);
		snprintf(request.add_vip.machine_id, VM_MACHINE_ID_STR_LEN,
				 "%s", request_.interfaceid().c_str());
		if (request_.interfacevipip().ipversion() == dpdkonmetal::IPVersion::IPv4) {
			request.add_vip.ip_type = RTE_ETHER_TYPE_IPV4;
			inet_aton(request_.interfacevipip().address().c_str(),
					  (in_addr*)&request.add_vip.vip.vip_addr);
		}
		dp_send_to_worker(&request);
		status_ = AWAIT_MSG;
		return -1;
	} else if (status_ == INITCHECK) {
		responder_.Finish(reply_, ret, this);
		status_ = FINISH;
	} else if (status_ == AWAIT_MSG) {
		dp_fill_head(&reply.com_head, call_type_, 0, 1);
		if (dp_recv_from_worker(&reply))
			return -1;
		status_ = FINISH;
		GRPCService* grpc_service = dynamic_cast<GRPCService*>(service_); 
		grpc_service->CalculateUnderlayRoute(reply.vni, buf_bin, sizeof(buf_bin));
		inet_ntop(AF_INET6, buf_bin, buf_str, INET6_ADDRSTRLEN);
		reply_.set_underlayroute(buf_str);
		err_status->set_error(reply.com_head.err_code);
		reply_.set_allocated_status(err_status);
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

	if (status_ == REQUEST) {
		new DelVIPCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		DPS_LOG(INFO, DPSERVICE, "GRPC delete VIP called for id: %s\n", request_.interfaceid().c_str());
		dp_fill_head(&request.com_head, call_type_, 0, 1);
		snprintf(request.del_vip.machine_id, VM_MACHINE_ID_STR_LEN,
				 "%s", request_.interfaceid().c_str());
		dp_send_to_worker(&request);
		status_ = AWAIT_MSG;
		return -1;
	} else if (status_ == INITCHECK) {
		responder_.Finish(reply_, ret, this);
		status_ = FINISH;
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

	if (status_ == REQUEST) {
		new GetVIPCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		DPS_LOG(INFO, DPSERVICE, "GRPC get VIP called for id: %s\n", request_.interfaceid().c_str());
		dp_fill_head(&request.com_head, call_type_, 0, 1);
		snprintf(request.get_vip.machine_id, VM_MACHINE_ID_STR_LEN,
				 "%s", request_.interfaceid().c_str());
		dp_send_to_worker(&request);
		status_ = AWAIT_MSG;
		return -1;
	} else if (status_ == INITCHECK) {
		responder_.Finish(reply_, ret, this);
		status_ = FINISH;
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

int AddInterfaceCall::Proceed()
{
	dp_request request = {0};
	dp_reply reply = {0};
	VirtualFunction *vf = new VirtualFunction();
	Status *err_status = new Status();
	IpAdditionResponse *ip_resp = new IpAdditionResponse();
	uint8_t buf_bin[16];
	char buf_str[INET6_ADDRSTRLEN];

	if (status_ == REQUEST) {
		new AddInterfaceCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		DPS_LOG(INFO, DPSERVICE, "GRPC add Interface called for id: %s IP: %s dpdk pci: %s\n",
				request_.interfaceid().c_str(), request_.ipv4config().primaryaddress().c_str(),
				request_.devicename().c_str());
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
				 request_.interfaceid().c_str());
		if (!err_status->error())
			dp_send_to_worker(&request);
		status_ = AWAIT_MSG;
		return -1;
	} else if (status_ == INITCHECK) {
		responder_.Finish(reply_, ret, this);
		status_ = FINISH;
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
		ip_resp->set_underlayroute(buf_str);
		ip_resp->set_allocated_status(err_status);
		reply_.set_allocated_response(ip_resp);
		status_ = FINISH;
		responder_.Finish(reply_, ret, this);
	} else {
		GPR_ASSERT(status_ == FINISH);
		delete this;
	}
	return 0;
}

int DelInterfaceCall::Proceed()
{
	dp_request request = {0};
	dp_reply reply= {0};

	if (status_ == REQUEST) {
		new DelInterfaceCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		DPS_LOG(INFO, DPSERVICE, "GRPC delete Interface called for id: %s\n",
				request_.interfaceid().c_str());
		dp_fill_head(&request.com_head, call_type_, 0, 1);
		snprintf(request.del_machine.machine_id, VM_MACHINE_ID_STR_LEN,
				 "%s", request_.interfaceid().c_str());
		dp_send_to_worker(&request);
		status_ = AWAIT_MSG;
		return -1;
	} else if (status_ == INITCHECK) {
		responder_.Finish(reply_, ret, this);
		status_ = FINISH;
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

int GetInterfaceCall::Proceed()
{
	dp_request request = {0};
	dp_reply reply = {0};
	dp_vm_info *vm_info;
	Status *err_status = new Status();
	Interface *machine = new Interface();
	struct in_addr addr;
	uint8_t buf_bin[16];
	char buf_str[INET6_ADDRSTRLEN];

	if (status_ == REQUEST) {
		new GetInterfaceCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		DPS_LOG(INFO, DPSERVICE, "GRPC get Interface called for id: %s\n",
				request_.interfaceid().c_str());
		dp_fill_head(&request.com_head, call_type_, 0, 1);
		snprintf(request.get_machine.machine_id, VM_MACHINE_ID_STR_LEN,
				 "%s", request_.interfaceid().c_str());
		dp_send_to_worker(&request);
		status_ = AWAIT_MSG;
		return -1;
	} else if (status_ == INITCHECK) {
		responder_.Finish(reply_, ret, this);
		status_ = FINISH;
	} else if (status_ == AWAIT_MSG) {
		dp_fill_head(&reply.com_head, call_type_, 0, 1);
		if (dp_recv_from_worker(&reply))
			return -1;

		vm_info = &reply.vm_info;
		addr.s_addr = htonl(vm_info->ip_addr);
		machine->set_primaryipv4address(inet_ntoa(addr));
		inet_ntop(AF_INET6, vm_info->ip6_addr, buf_str, INET6_ADDRSTRLEN);
		machine->set_primaryipv6address(buf_str);
		machine->set_interfaceid((char *)vm_info->machine_id);
		machine->set_vni(vm_info->vni);
		machine->set_pcidpname(vm_info->pci_name);

		GRPCService* grpc_service = dynamic_cast<GRPCService*>(service_); 
		grpc_service->CalculateUnderlayRoute(vm_info->vni, buf_bin, sizeof(buf_bin));
		inet_ntop(AF_INET6, buf_bin, buf_str, INET6_ADDRSTRLEN);
		machine->set_underlayroute(buf_str);
		reply_.set_allocated_interface(machine);
		err_status->set_error(reply.com_head.err_code);
		reply_.set_allocated_status(err_status);
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

	if (status_ == REQUEST) {
		new AddRouteCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		DPS_LOG(INFO, DPSERVICE, "GRPC add Route called with parameters vni: %d prefix: %s length %d target hop %s\n", 
				request_.vni().vni(), request_.route().prefix().address().c_str(), request_.route().prefix().prefixlength(),
				request_.route().nexthopaddress().c_str());
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
	} else if (status_ == INITCHECK) {
		responder_.Finish(reply_, ret, this);
		status_ = FINISH;
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

	if (status_ == REQUEST) {
		new DelRouteCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		DPS_LOG(INFO, DPSERVICE, "GRPC delete Route called\n");
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
	} else if (status_ == INITCHECK) {
		responder_.Finish(reply_, ret, this);
		status_ = FINISH;
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
	int i;
	uint8_t is_chained = 0;
	uint16_t read_so_far = 0;
	char buf[INET6_ADDRSTRLEN];

	if (status_ == REQUEST) {
		new ListRoutesCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		DPS_LOG(INFO, DPSERVICE, "GRPC list Routes called\n");
		dp_fill_head(&request.com_head, call_type_, 0, 1);
		request.route.vni = request_.vni();
		dp_send_to_worker(&request);
		status_ = AWAIT_MSG;
		return -1;
	} else if (status_ == INITCHECK) {
		responder_.Finish(reply_, ret, this);
		status_ = FINISH;
	} else if (status_ == AWAIT_MSG) {
		do {
			if (dp_recv_from_worker_with_mbuf(&mbuf))
				return -1;
			reply = rte_pktmbuf_mtod(mbuf, dp_reply*);
			for (i = 0; i < (reply->com_head.msg_count - read_so_far); i++) {
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
			read_so_far += (reply->com_head.msg_count - read_so_far);
			is_chained = reply->com_head.is_chained;
			rte_pktmbuf_free(mbuf);
		} while (is_chained);
		status_ = FINISH;
		responder_.Finish(reply_, ret, this);
	} else {
		GPR_ASSERT(status_ == FINISH);
		delete this;
	}
	return 0;
}

int ListInterfacesCall::Proceed()
{
	dp_request request = {0};
	struct rte_mbuf *mbuf = NULL;
	struct dp_reply *reply;
	Interface *machine;
	struct in_addr addr;
	dp_vm_info *vm_info;
	uint8_t is_chained = 0;
	uint16_t read_so_far = 0;
	int i;
	char buf_str[INET6_ADDRSTRLEN];
	uint8_t buf_bin[16];

	if (status_ == REQUEST) {
		new ListInterfacesCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		DPS_LOG(INFO, DPSERVICE, "GRPC list Interfaces called\n");
		dp_fill_head(&request.com_head, call_type_, 0, 1);
		dp_send_to_worker(&request);
		status_ = AWAIT_MSG;
		return -1;
	} else if (status_ == INITCHECK) {
		responder_.Finish(reply_, ret, this);
		status_ = FINISH;
	} else if (status_ == AWAIT_MSG) {
		GRPCService* grpc_service = dynamic_cast<GRPCService*>(service_); 
		do {
			if (dp_recv_from_worker_with_mbuf(&mbuf))
				return -1;
			reply = rte_pktmbuf_mtod(mbuf, dp_reply*);
			for (i = 0; i < (reply->com_head.msg_count - read_so_far); i++) {
				machine = reply_.add_interfaces();
				vm_info = &((&reply->vm_info)[i]);
				addr.s_addr = htonl(vm_info->ip_addr);
				machine->set_primaryipv4address(inet_ntoa(addr));
				inet_ntop(AF_INET6, vm_info->ip6_addr, buf_str, INET6_ADDRSTRLEN);
				machine->set_primaryipv6address(buf_str);
				machine->set_interfaceid((char *)vm_info->machine_id);
				machine->set_vni(vm_info->vni);
				machine->set_pcidpname(vm_info->pci_name);
				grpc_service->CalculateUnderlayRoute(vm_info->vni, buf_bin, sizeof(buf_bin));
				inet_ntop(AF_INET6, buf_bin, buf_str, INET6_ADDRSTRLEN);
				machine->set_underlayroute(buf_str);
			}
			read_so_far += (reply->com_head.msg_count - read_so_far);
			is_chained = reply->com_head.is_chained;
			rte_pktmbuf_free(mbuf);
		} while (is_chained);
		status_ = FINISH;
		responder_.Finish(reply_, ret, this);
	} else {
		GPR_ASSERT(status_ == FINISH);
		delete this;
	}
	return 0;
}
