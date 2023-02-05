#include "grpc/dp_async_grpc.h"
#include "grpc/dp_grpc_service.h"
#include "grpc/dp_grpc_impl.h"
#include <arpa/inet.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include "dp_error.h"
#include "dp_util.h"
#include "dp_lpm.h"
#include "dp_log.h"

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
		DPGRPC_LOG_INFO("init called");
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
	char buf_str[INET6_ADDRSTRLEN];
	int ret_val;

	if (status_ == REQUEST) {
		new CreateLBCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		DPGRPC_LOG_INFO("create LoadBalancer called for id: %s", request_.loadbalancerid().c_str());
		dp_fill_head(&request.com_head, call_type_, 0, 1);
		snprintf(request.add_lb.lb_id, DP_LB_ID_SIZE, "%s",
				 request_.loadbalancerid().c_str());
		request.add_lb.vni = request_.vni();
		if (request_.lbvipip().ipversion() == dpdkonmetal::IPVersion::IPv4) {
			request.add_lb.ip_type = RTE_ETHER_TYPE_IPV4;
			ret_val = inet_aton(request_.lbvipip().address().c_str(),
					  (in_addr*)&request.add_lb_vip.back.back_addr);
			if (ret_val == 0)
				DPGRPC_LOG_WARNING("CreateLB: Wrong loadbalancer vip ip %s", request_.lbvipip().address().c_str());
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
		inet_ntop(AF_INET6, reply.get_lb.ul_addr6, buf_str, INET6_ADDRSTRLEN);
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
		DPGRPC_LOG_INFO("delete LoadBalancer called for id: %s", request_.loadbalancerid().c_str());
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
	char buf_str[INET6_ADDRSTRLEN];
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
		DPGRPC_LOG_INFO("get LoadBalancer called for id: %s", request_.loadbalancerid().c_str());
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
		inet_ntop(AF_INET6, reply.get_lb.ul_addr6, buf_str, INET6_ADDRSTRLEN);
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

int AddLBVIPCall::Proceed()
{
	dp_request request = {0};
	dp_reply reply = {0};
	int ret_val;

	if (status_ == REQUEST) {
		new AddLBVIPCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		DPGRPC_LOG_INFO("add LoadBalancer target called for id: %s adding target %s",
				request_.loadbalancerid().c_str(), request_.targetip().address().c_str());
		dp_fill_head(&request.com_head, call_type_, 0, 1);
		snprintf(request.add_lb_vip.lb_id, DP_LB_ID_SIZE, "%s",
				 request_.loadbalancerid().c_str());
		if (request_.targetip().ipversion() == dpdkonmetal::IPVersion::IPv6) {
			request.add_lb_vip.ip_type = RTE_ETHER_TYPE_IPV6;
			ret_val = inet_pton(AF_INET6, request_.targetip().address().c_str(),
					  request.add_lb_vip.back.back_addr6);
			if (ret_val <= 0)
				DPGRPC_LOG_WARNING("AddLBVIP: wrong loadbalancer target ip: %s", request_.targetip().address().c_str());
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
	int ret_val;

	if (status_ == REQUEST) {
		new DelLBVIPCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		DPGRPC_LOG_INFO("delete LoadBalancer target called for id: %s", request_.loadbalancerid().c_str());
		dp_fill_head(&request.com_head, call_type_, 0, 1);
		snprintf(request.del_lb_vip.lb_id, DP_LB_ID_SIZE, "%s",
				 request_.loadbalancerid().c_str());
		if (request_.targetip().ipversion() == dpdkonmetal::IPVersion::IPv6) {
			request.del_lb_vip.ip_type = RTE_ETHER_TYPE_IPV6;
			ret_val = inet_pton(AF_INET6, request_.targetip().address().c_str(),
					  request.del_lb_vip.back.back_addr6);
			if (ret_val <= 0)
				DPGRPC_LOG_WARNING("DelLBVIP: wrong loadbalancer target ip: %s", request_.targetip().address().c_str());
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
		DPGRPC_LOG_INFO("list LoadBalancer targets called for id: %s", request_.loadbalancerid().c_str());
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
	GRPCService* grpc_service = dynamic_cast<GRPCService*>(service_);
	dp_request request = {0};
	dp_reply reply = {0};
	Status *err_status;
	uint8_t buf_bin[16];
	char buf_str[INET6_ADDRSTRLEN];
	int ret_val;

	if (status_ == REQUEST) {
		new AddPfxCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		DPGRPC_LOG_INFO("add AliasPrefix called for id: %s", request_.interfaceid().interfaceid().c_str());
		dp_fill_head(&request.com_head, call_type_, 0, 1);
		snprintf(request.add_pfx.machine_id, VM_MACHINE_ID_STR_LEN,
				 "%s", request_.interfaceid().interfaceid().c_str());
		if (request_.prefix().ipversion() == dpdkonmetal::IPVersion::IPv4) {
			request.add_pfx.pfx_ip_type = RTE_ETHER_TYPE_IPV4;
			ret_val = inet_aton(request_.prefix().address().c_str(),
					  (in_addr*)&request.add_pfx.pfx_ip.pfx_addr);
			if (ret_val == 0)
				DPGRPC_LOG_WARNING("AddPfx: wrong prefix ip %s", request_.prefix().address().c_str());
		}
		request.add_pfx.pfx_length = request_.prefix().prefixlength();
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

int DelPfxCall::Proceed()
{
	dp_request request = {0};
	dp_reply reply= {0};
	int ret_val;

	if (status_ == REQUEST) {
		new DelPfxCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		DPGRPC_LOG_INFO("delete AliasPrefix called for id: %s", request_.interfaceid().interfaceid().c_str());
		dp_fill_head(&request.com_head, call_type_, 0, 1);
		snprintf(request.add_pfx.machine_id, VM_MACHINE_ID_STR_LEN,
				 "%s", request_.interfaceid().interfaceid().c_str());
		if (request_.prefix().ipversion() == dpdkonmetal::IPVersion::IPv4) {
			request.add_pfx.pfx_ip_type = RTE_ETHER_TYPE_IPV4;
			ret_val = inet_aton(request_.prefix().address().c_str(),
					  (in_addr*)&request.add_pfx.pfx_ip.pfx_addr);
			if (ret_val == 0)
				DPGRPC_LOG_WARNING("DelPfx: wrong prefix ip %s", request_.prefix().address().c_str());
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
		DPGRPC_LOG_INFO("list AliasPrefix(es) called for id: %s", request_.interfaceid().c_str());
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

int CreateLBTargetPfxCall::Proceed()
{
	char buf_str[INET6_ADDRSTRLEN];
	dp_request request = {0};
	dp_reply reply = {0};
	Status *err_status;
	int ret_val;

	if (status_ == REQUEST) {
		new CreateLBTargetPfxCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		DPGRPC_LOG_INFO("CreateLBTargetPfx called for id: %s", request_.interfaceid().interfaceid().c_str());
		dp_fill_head(&request.com_head, call_type_, 0, 1);
		snprintf(request.add_pfx.machine_id, VM_MACHINE_ID_STR_LEN,
				 "%s", request_.interfaceid().interfaceid().c_str());
		if (request_.prefix().ipversion() == dpdkonmetal::IPVersion::IPv4) {
			request.add_pfx.pfx_ip_type = RTE_ETHER_TYPE_IPV4;
			ret_val = inet_aton(request_.prefix().address().c_str(),
					  (in_addr*)&request.add_pfx.pfx_ip.pfx_addr);
			if (ret_val == 0)
				DPGRPC_LOG_WARNING("CreateLBTargetPfx: wrong target pfx address: %s\n", request_.prefix().address().c_str());
		}
		request.add_pfx.pfx_length = request_.prefix().prefixlength();
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
		inet_ntop(AF_INET6, reply.route.trgt_ip.addr6, buf_str, INET6_ADDRSTRLEN);
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

int DelLBTargetPfxCall::Proceed()
{
	dp_request request = {0};
	dp_reply reply= {0};
	int ret_val;

	if (status_ == REQUEST) {
		new DelLBTargetPfxCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		DPGRPC_LOG_INFO("DelLBTargetPfx called for id: %s", request_.interfaceid().interfaceid().c_str());
		dp_fill_head(&request.com_head, call_type_, 0, 1);
		snprintf(request.add_pfx.machine_id, VM_MACHINE_ID_STR_LEN,
				 "%s", request_.interfaceid().interfaceid().c_str());
		if (request_.prefix().ipversion() == dpdkonmetal::IPVersion::IPv4) {
			request.add_pfx.pfx_ip_type = RTE_ETHER_TYPE_IPV4;
			ret_val = inet_aton(request_.prefix().address().c_str(),
					  (in_addr*)&request.add_pfx.pfx_ip.pfx_addr);
			if (ret_val == 0)
				DPGRPC_LOG_WARNING("DelLBTargetPfx: wrong target prefix address: %s\n", request_.prefix().address().c_str());
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

int ListLBTargetPfxCall::Proceed()
{
	char buf_str[INET6_ADDRSTRLEN];
	struct rte_mbuf *mbuf = NULL;
	dp_request request = {0};
	struct dp_reply *reply;
	struct in_addr addr;
	dp_route *rp_route;
	LBPrefix *pfx;
	int i;

	if (status_ == REQUEST) {
		new ListLBTargetPfxCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		DPGRPC_LOG_INFO("ListLBTargetPfxCall called for id: %s", request_.interfaceid().c_str());
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
				inet_ntop(AF_INET6, rp_route->trgt_ip.addr6, buf_str, INET6_ADDRSTRLEN);
				pfx->set_underlayroute(buf_str);
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
	Status *err_status;
	uint8_t buf_bin[16];
	char buf_str[INET6_ADDRSTRLEN];
	int ret_val;

	if (status_ == REQUEST) {
		new AddVIPCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		DPGRPC_LOG_INFO("add VIP called for id: %s", request_.interfaceid().c_str());
		dp_fill_head(&request.com_head, call_type_, 0, 1);
		snprintf(request.add_vip.machine_id, VM_MACHINE_ID_STR_LEN,
				 "%s", request_.interfaceid().c_str());
		if (request_.interfacevipip().ipversion() == dpdkonmetal::IPVersion::IPv4) {
			request.add_vip.ip_type = RTE_ETHER_TYPE_IPV4;
			ret_val = inet_aton(request_.interfacevipip().address().c_str(),
					  (in_addr*)&request.add_vip.vip.vip_addr);
			if (ret_val == 0)
				DPGRPC_LOG_WARNING("AddVIP: wrong ip: %s\n", request_.interfacevipip().address().c_str());
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

int DelVIPCall::Proceed()
{
	dp_request request = {0};
	dp_reply reply = {0};

	if (status_ == REQUEST) {
		new DelVIPCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		DPGRPC_LOG_INFO("delete VIP called for id: %s", request_.interfaceid().c_str());
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
	Status *err_status;
	struct in_addr addr;

	if (status_ == REQUEST) {
		new GetVIPCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		DPGRPC_LOG_INFO("get VIP called for id: %s", request_.interfaceid().c_str());
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

int AddInterfaceCall::Proceed()
{
	dp_request request = {0};
	dp_reply reply = {0};
	VirtualFunction *vf;
	Status *err_status;
	IpAdditionResponse *ip_resp;
	uint8_t buf_bin[16];
	char buf_str[INET6_ADDRSTRLEN];
	int ret_val;

	if (status_ == REQUEST) {
		new AddInterfaceCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		DPGRPC_LOG_INFO("add Interface called for id: %s IP: %s dpdk pci: %s",
				request_.interfaceid().c_str(), request_.ipv4config().primaryaddress().c_str(),
				request_.devicename().c_str());
		dp_fill_head(&request.com_head, call_type_, 0, 1);
		request.add_machine.vni = request_.vni();
		ret_val = inet_aton(request_.ipv4config().primaryaddress().c_str(),
				(in_addr*)&request.add_machine.ip4_addr);
		if (ret_val == 0)
			DPGRPC_LOG_WARNING("AddInterface: wrong primary ip: %s\n", request_.ipv4config().primaryaddress().c_str());
		if (!request_.ipv4config().pxeconfig().nextserver().empty()) {
			ret_val = inet_aton(request_.ipv4config().pxeconfig().nextserver().c_str(),
					(in_addr*)&request.add_machine.ip4_pxe_addr);
			if (ret_val == 0)
				DPGRPC_LOG_WARNING("AddInterface: wrong next server ip: %s\n", request_.ipv4config().pxeconfig().nextserver().c_str());
		}
		snprintf(request.add_machine.pxe_str, VM_MACHINE_PXE_STR_LEN, "%s",
				 request_.ipv4config().pxeconfig().bootfilename().c_str());
		snprintf(request.add_machine.name, sizeof(request.add_machine.name), "%s",
				 request_.devicename().c_str());
		ret_val = inet_pton(AF_INET6, request_.ipv6config().primaryaddress().c_str(),
								request.add_machine.ip6_addr6);
		if (ret_val <= 0)
			DPGRPC_LOG_WARNING("AddInterface: wrong ipv6 primary ip: %s\n", request_.ipv6config().primaryaddress().c_str());
		snprintf(request.add_machine.machine_id, VM_MACHINE_ID_STR_LEN, "%s",
				 request_.interfaceid().c_str());
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
		vf = new VirtualFunction();
		vf->set_name(reply.vf_pci.name);
		vf->set_bus(reply.vf_pci.bus);
		vf->set_domain(reply.vf_pci.domain);
		vf->set_slot(reply.vf_pci.slot);
		vf->set_function(reply.vf_pci.function);
		reply_.set_allocated_vf(vf);
		err_status = new Status();
		err_status->set_error(reply.com_head.err_code);
		GRPCService* grpc_service = dynamic_cast<GRPCService*>(service_);
		grpc_service->CalculateUnderlayRoute(request_.vni(), buf_bin, sizeof(buf_bin));
		inet_ntop(AF_INET6, buf_bin, buf_str, INET6_ADDRSTRLEN);
		ip_resp = new IpAdditionResponse();
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
		DPGRPC_LOG_INFO("delete Interface called for id: %s",
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
	Status *err_status;
	Interface *machine;
	struct in_addr addr;
	uint8_t buf_bin[16];
	char buf_str[INET6_ADDRSTRLEN];

	if (status_ == REQUEST) {
		new GetInterfaceCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		DPGRPC_LOG_INFO("get Interface called for id: %s",
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
		machine = new Interface();
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
		err_status = new Status();
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
	int ret_val;

	if (status_ == REQUEST) {
		new AddRouteCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		DPGRPC_LOG_INFO("add Route called with parameters vni: %d prefix: %s length %d target hop %s",
				request_.vni().vni(), request_.route().prefix().address().c_str(), request_.route().prefix().prefixlength(),
				request_.route().nexthopaddress().c_str());
		dp_fill_head(&request.com_head, call_type_, 0, 1);
		request.route.vni = request_.vni().vni();
		request.route.trgt_hop_ip_type = RTE_ETHER_TYPE_IPV6;
		request.route.trgt_vni = request_.route().nexthopvni();
		ret_val = inet_pton(AF_INET6, request_.route().nexthopaddress().c_str(),
				  request.route.trgt_ip.addr6);
		if (ret_val <= 0)
			DPGRPC_LOG_WARNING("AddRoute: wrong nexthop ip: %s\n", request_.route().nexthopaddress().c_str());
		request.route.pfx_length = request_.route().prefix().prefixlength();
		if(request_.route().prefix().ipversion() == dpdkonmetal::IPVersion::IPv4) {
			request.route.pfx_ip_type = RTE_ETHER_TYPE_IPV4;
			ret_val = inet_aton(request_.route().prefix().address().c_str(),
					(in_addr*)&request.route.pfx_ip.addr);
			if (ret_val == 0)
				DPGRPC_LOG_WARNING("AddRoute: wrong Prefix addr: %s\n", request_.route().prefix().address().c_str());
		} else {
			request.route.pfx_ip_type = RTE_ETHER_TYPE_IPV6;
			ret_val = inet_pton(AF_INET6, request_.route().prefix().address().c_str(),
					request.route.pfx_ip.addr6);
			if (ret_val <= 0)
				DPGRPC_LOG_WARNING("AddRoute: wrong ipv6 prefix addr: %s\n", request_.route().prefix().address().c_str());
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
	dp_reply reply = {0};
	int ret_val;

	if (status_ == REQUEST) {
		new DelRouteCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		DPGRPC_LOG_INFO("delete Route called");
		dp_fill_head(&request.com_head, call_type_, 0, 1);
		request.route.vni = request_.vni().vni();
		request.route.trgt_hop_ip_type = RTE_ETHER_TYPE_IPV6;
		request.route.trgt_vni = request_.route().nexthopvni();
		if (!request_.route().nexthopaddress().empty()) {
			ret_val = inet_pton(AF_INET6, request_.route().nexthopaddress().c_str(),
					request.route.trgt_ip.addr6);
			if (ret_val <= 0)
				DPGRPC_LOG_WARNING("DelRoute: wrong nexthop ip: %s\n", request_.route().nexthopaddress().c_str());
		}
		request.route.pfx_length = request_.route().prefix().prefixlength();
		if (request_.route().prefix().ipversion() == dpdkonmetal::IPVersion::IPv4) {
			request.route.pfx_ip_type = RTE_ETHER_TYPE_IPV4;
			ret_val = inet_aton(request_.route().prefix().address().c_str(),
					(in_addr*)&request.route.pfx_ip.addr);
			if (ret_val == 0)
				DPGRPC_LOG_WARNING("DelRoute: wrong prefix addr: %s\n", request_.route().prefix().address().c_str());
		} else {
			request.route.pfx_ip_type = RTE_ETHER_TYPE_IPV6;
			ret_val = inet_pton(AF_INET6, request_.route().prefix().address().c_str(),
					request.route.pfx_ip.addr6);
			if (ret_val <= 0)
				DPGRPC_LOG_WARNING("DelRoute: wrong ivv6 prefix addr: %s\n", request_.route().prefix().address().c_str());
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
		DPGRPC_LOG_INFO("list Routes called");
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

int AddNATVIPCall::Proceed()
{
	dp_request request = {0};
	struct dp_reply reply = {0};

	grpc::Status ret = grpc::Status::OK;
	Status *err_status;
	uint8_t buf_bin[16];
	char buf_str[INET6_ADDRSTRLEN];
	int ret_val;

	if (status_ == REQUEST) {
		new AddNATVIPCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		dp_fill_head(&request.com_head, call_type_, 0, 1);
		snprintf(request.add_nat_vip.machine_id, VM_MACHINE_ID_STR_LEN,
				 "%s", request_.interfaceid().c_str());
		if (request_.natvipip().ipversion() == dpdkonmetal::IPVersion::IPv4) {
			request.add_nat_vip.ip_type = RTE_ETHER_TYPE_IPV4;
			ret_val = inet_aton(request_.natvipip().address().c_str(),
					  (in_addr*)&request.add_nat_vip.vip.vip_addr);
			if (ret_val == 0)
				DPGRPC_LOG_WARNING("AddNATVIP: wrong nat vip addr: %s\n", request_.natvipip().address().c_str());
		}

		// maybe add a validity check here to ensure minport is not greater than 2^30
		request.add_nat_vip.port_range[0] = request_.minport();
		request.add_nat_vip.port_range[1] = request_.maxport();

		DPGRPC_LOG_INFO("AddNATVIP is called to add a local NAT entry: interface %s -> NAT IP %s, with port range [%d, %d)",
				 request_.interfaceid().c_str(), request_.natvipip().address().c_str(), request_.minport(), request_.maxport());
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

int GetNATVIPCall::Proceed()
{
	dp_request request = {0};
	dp_reply reply = {0};
	Status *err_status;
	struct in_addr addr;
	NATIP *nat_ip;

	if (status_ == REQUEST) {
		new GetNATVIPCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		DPGRPC_LOG_INFO("get NAT VIP called for id: %s", request_.interfaceid().c_str());
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
		nat_ip = new NATIP();
		addr.s_addr = reply.nat_entry.m_ip.addr;
		nat_ip->set_address(inet_ntoa(addr));
		nat_ip->set_ipversion(dpdkonmetal::IPVersion::IPv4);
		reply_.set_allocated_natvipip(nat_ip);
		reply_.set_maxport(reply.nat_entry.max_port);
		reply_.set_minport(reply.nat_entry.min_port);
		status_ = FINISH;
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

int DeleteNATVIPCall::Proceed()
{
	dp_request request = {0};
	dp_reply reply = {0};
	grpc::Status ret = grpc::Status::OK;

	if (status_ == REQUEST) {
		new DeleteNATVIPCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		dp_fill_head(&request.com_head, call_type_, 0, 1);
		snprintf(request.del_nat_vip.machine_id, VM_MACHINE_ID_STR_LEN,
				 "%s", request_.interfaceid().c_str());

		DPGRPC_LOG_INFO("DeleteNATVIP is called to delete a local NAT entry: interface %s",
				 request_.interfaceid().c_str());
		dp_send_to_worker(&request);
		status_ = AWAIT_MSG;
		return -1;
	} else if (status_ == INITCHECK) {
		responder_.Finish(reply_, ret, this);
		status_ = FINISH;
	}
	else if (status_ == AWAIT_MSG) {
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

int AddNeighborNATCall::Proceed()
{
	dp_request request = {0};
	struct dp_reply reply = {0};
	int ret_val;
	grpc::Status ret = grpc::Status::OK;

	if (status_ == REQUEST) {
		new AddNeighborNATCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		dp_fill_head(&request.com_head, call_type_, 0, 1);
		request.add_nat_neigh.type = DP_NETNAT_INFO_TYPE_NEIGHBOR;
		if (request_.natvipip().ipversion() == dpdkonmetal::IPVersion::IPv4) {
			request.add_nat_neigh.ip_type = RTE_ETHER_TYPE_IPV4;
			ret_val = inet_aton(request_.natvipip().address().c_str(),
					  (in_addr*)&request.add_nat_neigh.vip.vip_addr);
			if (ret_val == 0)
				DPGRPC_LOG_WARNING("AddNeighborNAT: wrong NAT IP %s\n", request_.natvipip().address().c_str());
		}

		// maybe add a validity check here to ensure minport is not greater than 2^30
		request.add_nat_neigh.vni = request_.vni();
		request.add_nat_neigh.port_range[0] = request_.minport();
		request.add_nat_neigh.port_range[1] = request_.maxport();
		ret_val = inet_pton(AF_INET6, request_.underlayroute().c_str(),
				request.add_nat_neigh.route);
		if (ret_val <= 0)
			DPGRPC_LOG_WARNING("AddNeighborNAT: wrong route IP %s\n", request_.underlayroute().c_str());
		DPGRPC_LOG_INFO("AddNeighborNAT is called to add a neigh NAT entry: NAT IP %s, port range [%d, %d) for vni %d, with route %s \n",
				request_.natvipip().address().c_str(), request_.minport(), request_.maxport(), request_.vni(), request_.underlayroute().c_str());
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

int DeleteNeighborNATCall::Proceed()
{
	dp_request request = {0};
	dp_reply reply = {0};
	grpc::Status ret = grpc::Status::OK;
	int ret_val;

	if (status_ == REQUEST) {
		new DeleteNeighborNATCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		dp_fill_head(&request.com_head, call_type_, 0, 1);
		request.del_nat_neigh.type = DP_NETNAT_INFO_TYPE_NEIGHBOR;

		if (request_.natvipip().ipversion() == dpdkonmetal::IPVersion::IPv4) {
			request.del_nat_neigh.ip_type = RTE_ETHER_TYPE_IPV4;
			ret_val = inet_aton(request_.natvipip().address().c_str(),
					  (in_addr*)&request.del_nat_neigh.vip.vip_addr);
			if (ret_val == 0)
				DPGRPC_LOG_WARNING("DeleteNeighborNAT: wrong NAT IP %s\n", request_.natvipip().address().c_str());
		}

		// maybe add a validity check here to ensure minport is not greater than 2^30
		request.del_nat_neigh.vni = request_.vni();
		request.del_nat_neigh.port_range[0] = request_.minport();
		request.del_nat_neigh.port_range[1] = request_.maxport();

		DPGRPC_LOG_INFO("DeleteNeighborNAT is called to delete a neigh NAT entry: NAT IP %s, port range [%d, %d) for vni %d",
				request_.natvipip().address().c_str(), request_.minport(), request_.maxport(), request_.vni());
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
		DPGRPC_LOG_INFO("list Interfaces called");
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

int GetNATInfoCall::Proceed()
{
	dp_request request = {0};
	grpc::Status ret = grpc::Status::OK;
	struct rte_mbuf *mbuf = NULL;
	struct dp_reply *reply;
	uint8_t is_chained = 0;
	uint16_t read_so_far = 0;
	int i;
	NATInfoEntry *rep_nat_entry;
	dp_nat_entry *dp_nat_item;
	struct in_addr addr;
	NATIP *nat_ip;
	char buf[INET6_ADDRSTRLEN];
	int ret_val;

	if (status_ == REQUEST) {
		new GetNATInfoCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;

		dp_fill_head(&request.com_head, call_type_, 0, 1);

		if (request_.natinfotype() == dpdkonmetal::NATInfoType::NATInfoLocal)
			request.get_nat_entry.type = DP_NETNAT_INFO_TYPE_LOCAL;
		else if (request_.natinfotype() == dpdkonmetal::NATInfoType::NATInfoNeigh)
			request.get_nat_entry.type = DP_NETNAT_INFO_TYPE_NEIGHBOR;

		if (request_.natvipip().ipversion() == dpdkonmetal::IPVersion::IPv4) {
			request.get_nat_entry.ip_type = RTE_ETHER_TYPE_IPV4;
			ret_val = inet_aton(request_.natvipip().address().c_str(),
					  (in_addr*)&request.get_nat_entry.vip.vip_addr);
			if (ret_val == 0)
				DPGRPC_LOG_WARNING("getNATInfo: wrong NAT addr%s", request_.natvipip().address().c_str());
		}

		DPGRPC_LOG_INFO("getNATInfo is called to get entries for NAT IP %s", request_.natvipip().address().c_str());
		dp_send_to_worker(&request);
		status_ = AWAIT_MSG;
		return -1;
	} else if (status_ == INITCHECK) {
		responder_.Finish(reply_, ret, this);
		status_ = FINISH;
	} else if (status_ == AWAIT_MSG) {
		if (request_.natvipip().ipversion() == dpdkonmetal::IPVersion::IPv4) {
			request.get_nat_entry.ip_type = RTE_ETHER_TYPE_IPV4;
			nat_ip = new NATIP();
			nat_ip->set_address(request_.natvipip().address().c_str());
			nat_ip->set_ipversion(request_.natvipip().ipversion());
			reply_.set_allocated_natvipip(nat_ip);
		}
		reply_.set_natinfotype(request_.natinfotype());
		do {
			if (dp_recv_from_worker_with_mbuf(&mbuf))
				return -1;
			reply = rte_pktmbuf_mtod(mbuf, dp_reply*);
			for (i = 0; i < (reply->com_head.msg_count - read_so_far); i++) {
				rep_nat_entry = reply_.add_natinfoentries();
				dp_nat_item = &((&reply->nat_entry)[i]);
				if (request_.natinfotype() == dpdkonmetal::NATInfoType::NATInfoLocal) {
					addr.s_addr = htonl(dp_nat_item->m_ip.addr);
					rep_nat_entry->set_ipversion(dpdkonmetal::IPVersion::IPv4);
					rep_nat_entry->set_address(inet_ntoa(addr));
				}
				if (request_.natinfotype() == dpdkonmetal::NATInfoType::NATInfoNeigh) {
					inet_ntop(AF_INET6, dp_nat_item->underlay_route, buf, INET6_ADDRSTRLEN);
					rep_nat_entry->set_underlayroute(buf);
				}
				rep_nat_entry->set_minport(dp_nat_item->min_port);
				rep_nat_entry->set_maxport(dp_nat_item->max_port);
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
