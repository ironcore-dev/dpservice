#include "grpc/dp_async_grpc.h"
#include <arpa/inet.h>
#include <rte_ether.h>
#include <rte_mbuf.h>
#include "dp_log.h"
#include "dp_lpm.h"
#include "dp_util.h"
#include "grpc/dp_grpc_queue.h"
#include "grpc/dp_grpc_service.h"

inline void BaseCall::SetErrStatus(Status *status, dp_reply *reply) {
	uint32_t err_code = reply->err_code;
	status->set_error(err_code);
	status->set_message(dp_grpc_strerror(err_code));
}

inline Status *BaseCall::CreateErrStatus(dp_reply *reply) {
	Status *err_status = new Status();
	SetErrStatus(err_status, reply);
	return err_status;
}

void BaseCall::ConvertGRPCFwallRuleToDPFWallRule(const FirewallRule *grpc_rule, struct dp_fwall_rule *dp_rule)
{
	int ret_val;

	snprintf(dp_rule->rule_id, DP_FIREWALL_ID_STR_LEN,
				"%s", grpc_rule->ruleid().c_str());
	if (grpc_rule->sourceprefix().ipversion() == dpdkonmetal::IPVersion::IPv4) {
		ret_val = inet_aton(grpc_rule->sourceprefix().address().c_str(),
					(in_addr*)&dp_rule->src_ip);
		if (ret_val == 0)
			DPGRPC_LOG_WARNING("Bad firewall rule, wrong source prefix address",
							   DP_LOG_FWRULE(grpc_rule->ruleid().c_str()),
							   DP_LOG_FWSRC(grpc_rule->sourceprefix().address().c_str()));
		if (grpc_rule->sourceprefix().prefixlength() != DP_FWALL_MATCH_ANY_LENGTH)
			dp_rule->src_ip_mask = ~((1 << (32 - grpc_rule->sourceprefix().prefixlength())) - 1);
		else
			dp_rule->src_ip_mask = DP_FWALL_MATCH_ANY_LENGTH;
	}

	if (grpc_rule->destinationprefix().ipversion() == dpdkonmetal::IPVersion::IPv4) {
		ret_val = inet_aton(grpc_rule->destinationprefix().address().c_str(),
					(in_addr*)&dp_rule->dest_ip);
		if (ret_val == 0)
			DPGRPC_LOG_WARNING("Bad firewall rule, wrong destination prefix address",
							   DP_LOG_FWRULE(grpc_rule->ruleid().c_str()),
							   DP_LOG_FWSRC(grpc_rule->destinationprefix().address().c_str()));
		if (grpc_rule->destinationprefix().prefixlength() != DP_FWALL_MATCH_ANY_LENGTH)
			dp_rule->dest_ip_mask = ~((1 << (32 - grpc_rule->destinationprefix().prefixlength())) - 1);
		else
			dp_rule->dest_ip_mask = DP_FWALL_MATCH_ANY_LENGTH;
	}

	if (grpc_rule->direction() == dpdkonmetal::Ingress)
		dp_rule->dir = DP_FWALL_INGRESS;
	else
		dp_rule->dir = DP_FWALL_EGRESS;

	if (grpc_rule->action() == dpdkonmetal::Accept)
		dp_rule->action = DP_FWALL_ACCEPT;
	else
		dp_rule->action = DP_FWALL_DROP;

	dp_rule->priority = grpc_rule->priority();

	switch (grpc_rule->protocolfilter().filter_case()) {
		case dpdkonmetal::ProtocolFilter::kTcpFieldNumber:
			dp_rule->protocol = IPPROTO_TCP;
			dp_rule->filter.tcp_udp.src_port.lower = grpc_rule->protocolfilter().tcp().srcportlower();
			dp_rule->filter.tcp_udp.dst_port.lower = grpc_rule->protocolfilter().tcp().dstportlower();
			dp_rule->filter.tcp_udp.src_port.upper = grpc_rule->protocolfilter().tcp().srcportupper();
			dp_rule->filter.tcp_udp.dst_port.upper = grpc_rule->protocolfilter().tcp().dstportupper();
			DPGRPC_LOG_INFO("Adding firewall rule filter",
							DP_LOG_FWRULE(grpc_rule->ruleid().c_str()),
							DP_LOG_FWPROTO(dp_rule->protocol),
							DP_LOG_FWSPORTFROM(dp_rule->filter.tcp_udp.src_port.lower),
							DP_LOG_FWSPORTTO(dp_rule->filter.tcp_udp.src_port.upper),
							DP_LOG_FWDPORTFROM(dp_rule->filter.tcp_udp.dst_port.lower),
							DP_LOG_FWDPORTTO(dp_rule->filter.tcp_udp.dst_port.upper));
		break;
		case dpdkonmetal::ProtocolFilter::kUdpFieldNumber:
			dp_rule->protocol = IPPROTO_UDP;
			dp_rule->filter.tcp_udp.src_port.lower = grpc_rule->protocolfilter().udp().srcportlower();
			dp_rule->filter.tcp_udp.dst_port.lower = grpc_rule->protocolfilter().udp().dstportlower();
			dp_rule->filter.tcp_udp.src_port.upper = grpc_rule->protocolfilter().udp().srcportupper();
			dp_rule->filter.tcp_udp.dst_port.upper = grpc_rule->protocolfilter().udp().dstportupper();
			DPGRPC_LOG_INFO("Adding firewall rule filter",
							DP_LOG_FWRULE(grpc_rule->ruleid().c_str()),
							DP_LOG_FWPROTO(dp_rule->protocol),
							DP_LOG_FWSPORTFROM(dp_rule->filter.tcp_udp.src_port.lower),
							DP_LOG_FWSPORTTO(dp_rule->filter.tcp_udp.src_port.upper),
							DP_LOG_FWDPORTFROM(dp_rule->filter.tcp_udp.dst_port.lower),
							DP_LOG_FWDPORTTO(dp_rule->filter.tcp_udp.dst_port.upper));
		break;
		case dpdkonmetal::ProtocolFilter::kIcmpFieldNumber:
			dp_rule->protocol = IPPROTO_ICMP;
			dp_rule->filter.icmp.icmp_type = grpc_rule->protocolfilter().icmp().icmptype();
			dp_rule->filter.icmp.icmp_code = grpc_rule->protocolfilter().icmp().icmpcode();
			DPGRPC_LOG_INFO("Adding firewall rule filter",
							DP_LOG_FWRULE(grpc_rule->ruleid().c_str()),
							DP_LOG_FWPROTO(dp_rule->protocol),
							DP_LOG_FWICMPTYPE(dp_rule->filter.icmp.icmp_type),
							DP_LOG_FWICMPCODE(dp_rule->filter.icmp.icmp_code));
		break;
		case dpdkonmetal::ProtocolFilter::FILTER_NOT_SET:
		default:
			dp_rule->protocol = DP_FWALL_MATCH_ANY_PROTOCOL;
			dp_rule->filter.tcp_udp.src_port.lower = DP_FWALL_MATCH_ANY_PORT;
			dp_rule->filter.tcp_udp.dst_port.lower = DP_FWALL_MATCH_ANY_PORT;
			DPGRPC_LOG_INFO("Adding firewall rule filter",
							DP_LOG_FWRULE(grpc_rule->ruleid().c_str()),
							DP_LOG_FWPROTO(dp_rule->protocol));
	}
}

void BaseCall::ConvertDPFWallRuleToGRPCFwallRule(struct dp_fwall_rule	*dp_rule, FirewallRule *grpc_rule)
{
	ICMPFilter *icmp_filter;
	ProtocolFilter *filter;
	TCPFilter *tcp_filter;
	UDPFilter *udp_filter;
	struct in_addr addr;
	Prefix *src_ip;
	Prefix *dst_ip;

	grpc_rule->set_ruleid(dp_rule->rule_id);
	grpc_rule->set_ipversion(dpdkonmetal::IPVersion::IPv4);
	grpc_rule->set_priority(dp_rule->priority);
	if (dp_rule->dir == DP_FWALL_INGRESS)
		grpc_rule->set_direction(dpdkonmetal::Ingress);
	else
		grpc_rule->set_direction(dpdkonmetal::Egress);

	if (dp_rule->action == DP_FWALL_ACCEPT)
		grpc_rule->set_action(dpdkonmetal::Accept);
	else
		grpc_rule->set_action(dpdkonmetal::Drop);

	src_ip = new Prefix();
	src_ip->set_ipversion(dpdkonmetal::IPVersion::IPv4);
	addr.s_addr = dp_rule->src_ip;
	src_ip->set_address(inet_ntoa(addr));
	src_ip->set_prefixlength(__builtin_popcount(dp_rule->src_ip_mask));
	grpc_rule->set_allocated_sourceprefix(src_ip);

	dst_ip = new Prefix();
	dst_ip->set_ipversion(dpdkonmetal::IPVersion::IPv4);
	addr.s_addr = dp_rule->dest_ip;
	dst_ip->set_address(inet_ntoa(addr));
	dst_ip->set_prefixlength(__builtin_popcount(dp_rule->dest_ip_mask));
	grpc_rule->set_allocated_destinationprefix(dst_ip);

	filter = new ProtocolFilter();
	if (dp_rule->protocol == IPPROTO_TCP) {
		tcp_filter = new TCPFilter();
		tcp_filter->set_dstportlower(dp_rule->filter.tcp_udp.dst_port.lower);
		tcp_filter->set_dstportupper(dp_rule->filter.tcp_udp.dst_port.upper);
		tcp_filter->set_srcportlower(dp_rule->filter.tcp_udp.src_port.lower);
		tcp_filter->set_srcportupper(dp_rule->filter.tcp_udp.src_port.upper);
		filter->set_allocated_tcp(tcp_filter);
		grpc_rule->set_allocated_protocolfilter(filter);
	}
	if (dp_rule->protocol == IPPROTO_UDP) {
		udp_filter = new UDPFilter();
		udp_filter->set_dstportlower(dp_rule->filter.tcp_udp.dst_port.lower);
		udp_filter->set_dstportupper(dp_rule->filter.tcp_udp.dst_port.upper);
		udp_filter->set_srcportlower(dp_rule->filter.tcp_udp.src_port.lower);
		udp_filter->set_srcportupper(dp_rule->filter.tcp_udp.src_port.upper);
		filter->set_allocated_udp(udp_filter);
		grpc_rule->set_allocated_protocolfilter(filter);
	}
	if (dp_rule->protocol == IPPROTO_ICMP) {
		icmp_filter = new ICMPFilter();
		icmp_filter->set_icmpcode(dp_rule->filter.icmp.icmp_code);
		icmp_filter->set_icmptype(dp_rule->filter.icmp.icmp_type);
		filter->set_allocated_icmp(icmp_filter);
		grpc_rule->set_allocated_protocolfilter(filter);
	}
}

int IsVniInUseCall::Proceed()
{
	dp_request request = {
		.type = call_type_,
	};
	dp_reply reply;

	if (status_ == REQUEST) {
		new IsVniInUseCall(service_, cq_);
		switch (request_.type()) {
		case VniIpv4:
			request.vni_in_use.type = DP_VNI_IPV4;
			break;
		case VniIpv6:
			request.vni_in_use.type = DP_VNI_IPV6;
			break;
		default:
			request.vni_in_use.type = DP_VNI_IPV4;
			break;
		}
		request.vni_in_use.vni = request_.vni();
		DPGRPC_LOG_INFO("Checking VNI usage", DP_LOG_VNI(request.vni_in_use.vni),
						DP_LOG_VNI_TYPE(request.vni_in_use.type));
		dp_send_to_worker(&request);  // TODO can fail
		status_ = AWAIT_MSG;
		return -1;
	} else if (status_ == AWAIT_MSG) {
		if (DP_FAILED(dp_recv_from_worker(&reply, call_type_)))  // TODO can fail (this `return -1` is only a wait loop)
			return -1;

		if (reply.vni_in_use.in_use)
			reply_.set_inuse(true);
		else
			reply_.set_inuse(false);

		reply_.set_allocated_status(CreateErrStatus(&reply));
		status_ = FINISH;
		responder_.Finish(reply_, ret, this);
	} else {
		GPR_ASSERT(status_ == FINISH);
		delete this;
	}
	return 0;
}

int ResetVniCall::Proceed()
{
	dp_request request = {
		.type = call_type_,
	};
	dp_reply reply;

	if (status_ == REQUEST) {
		new ResetVniCall(service_, cq_);
		switch (request_.type()) {
		case VniIpv4:
			request.vni_in_use.type = DP_VNI_IPV4;
			break;
		case VniIpv6:
			request.vni_in_use.type = DP_VNI_IPV6;
			break;
		case VniIpv4AndIpv6:
			request.vni_in_use.type = DP_VNI_BOTH;
			break;
		default:
			request.vni_in_use.type = DP_VNI_BOTH;
			break;
		}
		request.vni_in_use.vni = request_.vni();
		DPGRPC_LOG_INFO("Resetting VNI", DP_LOG_VNI(request.vni_in_use.vni),
						DP_LOG_VNI_TYPE(request.vni_in_use.type));
		dp_send_to_worker(&request);  // TODO can fail
		status_ = AWAIT_MSG;
		return -1;
	} else if (status_ == AWAIT_MSG) {
		if (DP_FAILED(dp_recv_from_worker(&reply, call_type_)))  // TODO can fail (this `return -1` is only a wait loop)
			return -1;

		SetErrStatus(&reply_, &reply);
		status_ = FINISH;
		responder_.Finish(reply_, ret, this);
	} else {
		GPR_ASSERT(status_ == FINISH);
		delete this;
	}
	return 0;
}

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
	dp_request request = {
		.type = call_type_,
	};
	dp_reply reply;

	if (status_ == REQUEST) {
		new InitCall(service_, cq_);
		dp_send_to_worker(&request);  // TODO can fail
		status_ = AWAIT_MSG;
		DPGRPC_LOG_INFO("Initializing");
		return -1;
	} else if (status_ == AWAIT_MSG) {
		GRPCService* grpc_service = dynamic_cast<GRPCService*>(service_);
		grpc_service->SetInitStatus(true);
		if (DP_FAILED(dp_recv_from_worker(&reply, call_type_)))  // TODO can fail (this `return -1` is only a wait loop)
			return -1;
		SetErrStatus(&reply_, &reply);
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
	dp_request request = {
		.type = call_type_,
	};
	dp_reply reply;
	uint16_t i, size;
	char buf_str[INET6_ADDRSTRLEN];
	int ret_val;

	if (status_ == REQUEST) {
		new CreateLBCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		DPGRPC_LOG_INFO("Creating loadbalancer",
						DP_LOG_LBID(request_.loadbalancerid().c_str()),
						DP_LOG_VNI(request_.vni()),
						DP_LOG_IPV4STR(request_.lbvipip().address().c_str()));
		snprintf(request.add_lb.lb_id, DP_LB_ID_SIZE, "%s",
				 request_.loadbalancerid().c_str());
		request.add_lb.vni = request_.vni();
		if (request_.lbvipip().ipversion() == dpdkonmetal::IPVersion::IPv4) {
			request.add_lb.ip_type = RTE_ETHER_TYPE_IPV4;
			ret_val = inet_aton(request_.lbvipip().address().c_str(),
					  (in_addr*)&request.add_lb_vip.back.back_addr);
			if (ret_val == 0)
				DPGRPC_LOG_WARNING("Invalid loadbalancer VIP",
								   DP_LOG_IPV4STR(request_.lbvipip().address().c_str()));
			size = (request_.lbports_size() >= DP_LB_PORT_SIZE) ? DP_LB_PORT_SIZE : request_.lbports_size();
			for (i = 0; i < size; i++) {
				DPGRPC_LOG_INFO("Adding loadbalancer port",
								DP_LOG_LBID(request_.loadbalancerid().c_str()),
								DP_LOG_PORT(request_.lbports(i).port()),
								DP_LOG_PROTO(request_.lbports(i).protocol()));
				request.add_lb.lbports[i].port = request_.lbports(i).port();
				if (request_.lbports(i).protocol() == TCP)
					request.add_lb.lbports[i].protocol = DP_IP_PROTO_TCP;
				if (request_.lbports(i).protocol() == UDP)
					request.add_lb.lbports[i].protocol = DP_IP_PROTO_UDP;
			}
		} else {
			request.add_lb.ip_type = RTE_ETHER_TYPE_IPV4;
			// FIXME: what happens here?
		}
		dp_send_to_worker(&request);  // TODO can fail
		status_ = AWAIT_MSG;
		return -1;
	} else if (status_ == INITCHECK) {
		responder_.Finish(reply_, ret, this);
		status_ = FINISH;
	} else if (status_ == AWAIT_MSG) {
		if (DP_FAILED(dp_recv_from_worker(&reply, call_type_)))  // TODO can fail (this `return -1` is only a wait loop)
			return -1;
		status_ = FINISH;
		inet_ntop(AF_INET6, reply.get_lb.ul_addr6, buf_str, INET6_ADDRSTRLEN);
		reply_.set_underlayroute(buf_str);
		reply_.set_allocated_status(CreateErrStatus(&reply));
		responder_.Finish(reply_, ret, this);
	} else {
		GPR_ASSERT(status_ == FINISH);
		delete this;
	}
	return 0;
}

int DelLBCall::Proceed()
{
	dp_request request = {
		.type = call_type_,
	};
	dp_reply reply;

	if (status_ == REQUEST) {
		new DelLBCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		DPGRPC_LOG_INFO("Removing loadbalancer",
						DP_LOG_LBID(request_.loadbalancerid().c_str()));
		snprintf(request.del_lb.lb_id, DP_LB_ID_SIZE, "%s",
				 request_.loadbalancerid().c_str());
		dp_send_to_worker(&request);  // TODO can fail
		status_ = AWAIT_MSG;
		return -1;
	} else if (status_ == INITCHECK) {
		responder_.Finish(reply_, ret, this);
		status_ = FINISH;
	} else if (status_ == AWAIT_MSG) {
		if (DP_FAILED(dp_recv_from_worker(&reply, call_type_)))  // TODO can fail (this `return -1` is only a wait loop)
			return -1;
		status_ = FINISH;
		SetErrStatus(&reply_, &reply);
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
	dp_request request = {
		.type = call_type_,
	};
	dp_reply reply;
	struct in_addr addr;
	LBPort *lb_port;
	LBIP *lb_ip;
	int i;

	if (status_ == REQUEST) {
		new GetLBCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		DPGRPC_LOG_INFO("Getting loadbalancer info",
						DP_LOG_LBID(request_.loadbalancerid().c_str()));
		snprintf(request.add_lb.lb_id, DP_LB_ID_SIZE, "%s",
				 request_.loadbalancerid().c_str());
		dp_send_to_worker(&request);  // TODO can fail
		status_ = AWAIT_MSG;
		return -1;
	} else if (status_ == INITCHECK) {
		responder_.Finish(reply_, ret, this);
		status_ = FINISH;
	} else if (status_ == AWAIT_MSG) {
		if (DP_FAILED(dp_recv_from_worker(&reply, call_type_)))  // TODO can fail (this `return -1` is only a wait loop)
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
		reply_.set_allocated_status(CreateErrStatus(&reply));
		responder_.Finish(reply_, ret, this);
	} else {
		GPR_ASSERT(status_ == FINISH);
		delete this;
	}
	return 0;
}

int AddLBVIPCall::Proceed()
{
	dp_request request = {
		.type = call_type_,
	};
	dp_reply reply;
	int ret_val;

	if (status_ == REQUEST) {
		new AddLBVIPCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		DPGRPC_LOG_INFO("Adding loadbalancer target",
						DP_LOG_LBID(request_.loadbalancerid().c_str()),
						DP_LOG_IPV6STR(request_.targetip().address().c_str()));
		snprintf(request.add_lb_vip.lb_id, DP_LB_ID_SIZE, "%s",
				 request_.loadbalancerid().c_str());
		if (request_.targetip().ipversion() == dpdkonmetal::IPVersion::IPv6) {
			request.add_lb_vip.ip_type = RTE_ETHER_TYPE_IPV6;
			ret_val = inet_pton(AF_INET6, request_.targetip().address().c_str(),
					  request.add_lb_vip.back.back_addr6);
			if (ret_val <= 0)
				DPGRPC_LOG_WARNING("Invalid loadbalancer target IP",
								   DP_LOG_IPV6STR(request_.targetip().address().c_str()));
		} else {
			request.add_lb_vip.ip_type = RTE_ETHER_TYPE_IPV4;
		}
		dp_send_to_worker(&request);  // TODO can fail
		status_ = AWAIT_MSG;
		return -1;
	} else if (status_ == INITCHECK) {
		responder_.Finish(reply_, ret, this);
		status_ = FINISH;
	} else if (status_ == AWAIT_MSG) {
		if (DP_FAILED(dp_recv_from_worker(&reply, call_type_)))  // TODO can fail (this `return -1` is only a wait loop)
			return -1;
		status_ = FINISH;
		SetErrStatus(&reply_, &reply);
		responder_.Finish(reply_, ret, this);
	} else {
		GPR_ASSERT(status_ == FINISH);
		delete this;
	}
	return 0;
}

int DelLBVIPCall::Proceed()
{
	dp_request request = {
		.type = call_type_,
	};
	dp_reply reply;
	int ret_val;

	if (status_ == REQUEST) {
		new DelLBVIPCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		DPGRPC_LOG_INFO("Removing loadbalancer target",
						DP_LOG_LBID(request_.loadbalancerid().c_str()),
						DP_LOG_IPV6STR(request_.targetip().address().c_str()));
		snprintf(request.del_lb_vip.lb_id, DP_LB_ID_SIZE, "%s",
				 request_.loadbalancerid().c_str());
		if (request_.targetip().ipversion() == dpdkonmetal::IPVersion::IPv6) {
			request.del_lb_vip.ip_type = RTE_ETHER_TYPE_IPV6;
			ret_val = inet_pton(AF_INET6, request_.targetip().address().c_str(),
					  request.del_lb_vip.back.back_addr6);
			if (ret_val <= 0)
				DPGRPC_LOG_WARNING("Invalid loadbalancer target IP",
								   DP_LOG_IPV6STR(request_.targetip().address().c_str()));
		} else {
			request.del_lb_vip.ip_type = RTE_ETHER_TYPE_IPV4;
		}
		dp_send_to_worker(&request);  // TODO can fail
		status_ = AWAIT_MSG;
		return -1;
	} else if (status_ == INITCHECK) {
		responder_.Finish(reply_, ret, this);
		status_ = FINISH;
	} else if (status_ == AWAIT_MSG) {
		if (DP_FAILED(dp_recv_from_worker(&reply, call_type_)))  // TODO can fail (this `return -1` is only a wait loop)
			return -1;
		status_ = FINISH;
		SetErrStatus(&reply_, &reply);
		responder_.Finish(reply_, ret, this);
	} else {
		GPR_ASSERT(status_ == FINISH);
		delete this;
	}
	return 0;
}

void GetLBVIPBackendsCall::ListCallback(void *reply, void *context)
{
	dp_lb_backip *rep_back_ip = (dp_lb_backip *)reply;
	GetLoadBalancerTargetsResponse *reply_ = (GetLoadBalancerTargetsResponse *)context;
	LBIP *back_ip;
	char buf_str[INET6_ADDRSTRLEN];

	back_ip = reply_->add_targetips();
	inet_ntop(AF_INET6, rep_back_ip->b_ip.addr6, buf_str, INET6_ADDRSTRLEN);
	back_ip->set_address(buf_str);
	back_ip->set_ipversion(dpdkonmetal::IPVersion::IPv6);
}

int GetLBVIPBackendsCall::Proceed()
{
	dp_request request = {
		.type = call_type_,
	};

	if (status_ == REQUEST) {
		new GetLBVIPBackendsCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		DPGRPC_LOG_INFO("Listing loadbalancer targets",
						DP_LOG_LBID(request_.loadbalancerid().c_str()));
		snprintf(request.qry_lb_vip.lb_id, DP_LB_ID_SIZE, "%s",
				 request_.loadbalancerid().c_str());
		dp_send_to_worker(&request);  // TODO can fail
		status_ = AWAIT_MSG;
		return -1;
	} else if (status_ == INITCHECK) {
		responder_.Finish(reply_, ret, this);
		status_ = FINISH;
	} else if (status_ == AWAIT_MSG) {
		// TODO can fail hard (this `return -1` is only a wait loop)
		if (DP_FAILED(dp_recv_array_from_worker(sizeof(dp_lb_backip), ListCallback, &reply_, call_type_)))
			return -1;
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
	dp_request request = {
		.type = call_type_,
	};
	dp_reply reply;
	char buf_str[INET6_ADDRSTRLEN];
	int ret_val;

	if (status_ == REQUEST) {
		new AddPfxCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		DPGRPC_LOG_INFO("Adding alias prefix",
						DP_LOG_IFACE(request_.interfaceid().interfaceid().c_str()),
						DP_LOG_PREFIX(request_.prefix().address().c_str()),
						DP_LOG_PREFLEN(request_.prefix().prefixlength()));
		snprintf(request.add_pfx.machine_id, VM_MACHINE_ID_STR_LEN,
				 "%s", request_.interfaceid().interfaceid().c_str());
		if (request_.prefix().ipversion() == dpdkonmetal::IPVersion::IPv4) {
			request.add_pfx.pfx_ip_type = RTE_ETHER_TYPE_IPV4;
			ret_val = inet_aton(request_.prefix().address().c_str(),
					  (in_addr*)&request.add_pfx.pfx_ip.pfx_addr);
			if (ret_val == 0)
				DPGRPC_LOG_WARNING("Invalid alias prefix IP",
								   DP_LOG_IPV4STR(request_.prefix().address().c_str()));
		}
		request.add_pfx.pfx_length = request_.prefix().prefixlength();
		dp_send_to_worker(&request);  // TODO can fail
		status_ = AWAIT_MSG;
		return -1;
	} else if (status_ == INITCHECK) {
		responder_.Finish(reply_, ret, this);
		status_ = FINISH;
	} else if (status_ == AWAIT_MSG) {
		if (DP_FAILED(dp_recv_from_worker(&reply, call_type_)))  // TODO can fail (this `return -1` is only a wait loop)
			return -1;
		status_ = FINISH;
		inet_ntop(AF_INET6, reply.ul_addr6, buf_str, INET6_ADDRSTRLEN);
		reply_.set_underlayroute(buf_str);
		reply_.set_allocated_status(CreateErrStatus(&reply));
		responder_.Finish(reply_, ret, this);
	} else {
		GPR_ASSERT(status_ == FINISH);
		delete this;
	}
	return 0;
}

int DelPfxCall::Proceed()
{
	dp_request request = {
		.type = call_type_,
	};
	dp_reply reply;
	int ret_val;

	if (status_ == REQUEST) {
		new DelPfxCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		DPGRPC_LOG_INFO("Removing alias prefix",
						DP_LOG_IFACE(request_.interfaceid().interfaceid().c_str()),
						DP_LOG_PREFIX(request_.prefix().address().c_str()),
						DP_LOG_PREFLEN(request_.prefix().prefixlength()));
		snprintf(request.add_pfx.machine_id, VM_MACHINE_ID_STR_LEN,
				 "%s", request_.interfaceid().interfaceid().c_str());
		if (request_.prefix().ipversion() == dpdkonmetal::IPVersion::IPv4) {
			request.add_pfx.pfx_ip_type = RTE_ETHER_TYPE_IPV4;
			ret_val = inet_aton(request_.prefix().address().c_str(),
					  (in_addr*)&request.add_pfx.pfx_ip.pfx_addr);
			if (ret_val == 0)
				DPGRPC_LOG_WARNING("Invalid alias prefix IP",
								   DP_LOG_PREFIX(request_.prefix().address().c_str()));
		}
		request.add_pfx.pfx_length = request_.prefix().prefixlength();
		dp_send_to_worker(&request);  // TODO can fail
		status_ = AWAIT_MSG;
		return -1;
	} else if (status_ == INITCHECK) {
		responder_.Finish(reply_, ret, this);
		status_ = FINISH;
	} else if (status_ == AWAIT_MSG) {
		if (DP_FAILED(dp_recv_from_worker(&reply, call_type_)))  // TODO can fail (this `return -1` is only a wait loop)
			return -1;
		SetErrStatus(&reply_, &reply);
		status_ = FINISH;
		responder_.Finish(reply_, ret, this);
	} else {
		GPR_ASSERT(status_ == FINISH);
		delete this;
	}
	return 0;
}

void ListPfxCall::ListCallback(void *reply, void *context)
{
	dp_route *rp_route = (dp_route *)reply;
	PrefixesMsg *reply_ = (PrefixesMsg *)context;
	Prefix *pfx;
	struct in_addr addr;
	char buf_str[INET6_ADDRSTRLEN];

	pfx = reply_->add_prefixes();
	if (rp_route->pfx_ip_type == RTE_ETHER_TYPE_IPV4) {
		addr.s_addr = htonl(rp_route->pfx_ip.addr);
		pfx->set_address(inet_ntoa(addr));
		pfx->set_ipversion(dpdkonmetal::IPVersion::IPv4);
		pfx->set_prefixlength(rp_route->pfx_length);
		inet_ntop(AF_INET6, rp_route->trgt_ip.addr6, buf_str, INET6_ADDRSTRLEN);
		pfx->set_underlayroute(buf_str);
	}
	// TODO else? (should already be covered by the worker)
}

int ListPfxCall::Proceed()
{
	dp_request request = {
		.type = call_type_,
	};

	if (status_ == REQUEST) {
		new ListPfxCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		DPGRPC_LOG_INFO("Listing alias prefixes",
						DP_LOG_IFACE(request_.interfaceid().c_str()));
		snprintf(request.get_pfx.machine_id, VM_MACHINE_ID_STR_LEN,
				 "%s", request_.interfaceid().c_str());
		dp_send_to_worker(&request);  // TODO can fail
		status_ = AWAIT_MSG;
		return -1;
	} else if (status_ == INITCHECK) {
		responder_.Finish(reply_, ret, this);
		status_ = FINISH;
	} else if (status_ == AWAIT_MSG) {
		// TODO can fail hard (this `return -1` is only a wait loop)
		if (DP_FAILED(dp_recv_array_from_worker(sizeof(dp_route), ListCallback, &reply_, call_type_)))
			return -1;
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
	dp_request request = {
		.type = call_type_,
	};
	dp_reply reply;
	int ret_val;

	if (status_ == REQUEST) {
		new CreateLBTargetPfxCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		DPGRPC_LOG_INFO("Adding loadbalancer target prefix",
						DP_LOG_IFACE(request_.interfaceid().interfaceid().c_str()),
						DP_LOG_PREFIX(request_.prefix().address().c_str()),
						DP_LOG_PREFLEN(request_.prefix().prefixlength()));
		snprintf(request.add_pfx.machine_id, VM_MACHINE_ID_STR_LEN,
				 "%s", request_.interfaceid().interfaceid().c_str());
		if (request_.prefix().ipversion() == dpdkonmetal::IPVersion::IPv4) {
			request.add_pfx.pfx_ip_type = RTE_ETHER_TYPE_IPV4;
			ret_val = inet_aton(request_.prefix().address().c_str(),
					  (in_addr*)&request.add_pfx.pfx_ip.pfx_addr);
			if (ret_val == 0)
				DPGRPC_LOG_WARNING("Invalid target prefix IP",
								   DP_LOG_PREFIX(request_.prefix().address().c_str()));
		}
		request.add_pfx.pfx_length = request_.prefix().prefixlength();
		dp_send_to_worker(&request);  // TODO can fail
		status_ = AWAIT_MSG;
		return -1;
	} else if (status_ == INITCHECK) {
		responder_.Finish(reply_, ret, this);
		status_ = FINISH;
	} else if (status_ == AWAIT_MSG) {
		if (DP_FAILED(dp_recv_from_worker(&reply, call_type_)))  // TODO can fail (this `return -1` is only a wait loop)
			return -1;
		status_ = FINISH;
		inet_ntop(AF_INET6, reply.route.trgt_ip.addr6, buf_str, INET6_ADDRSTRLEN);
		reply_.set_underlayroute(buf_str);
		reply_.set_allocated_status(CreateErrStatus(&reply));
		responder_.Finish(reply_, ret, this);
	} else {
		GPR_ASSERT(status_ == FINISH);
		delete this;
	}
	return 0;
}

int DelLBTargetPfxCall::Proceed()
{
	dp_request request = {
		.type = call_type_,
	};
	dp_reply reply;
	int ret_val;

	if (status_ == REQUEST) {
		new DelLBTargetPfxCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		DPGRPC_LOG_INFO("Removing loadbalancer target prefix",
						DP_LOG_IFACE(request_.interfaceid().interfaceid().c_str()),
						DP_LOG_PREFIX(request_.prefix().address().c_str()),
						DP_LOG_PREFLEN(request_.prefix().prefixlength()));
		snprintf(request.add_pfx.machine_id, VM_MACHINE_ID_STR_LEN,
				 "%s", request_.interfaceid().interfaceid().c_str());
		if (request_.prefix().ipversion() == dpdkonmetal::IPVersion::IPv4) {
			request.add_pfx.pfx_ip_type = RTE_ETHER_TYPE_IPV4;
			ret_val = inet_aton(request_.prefix().address().c_str(),
					  (in_addr*)&request.add_pfx.pfx_ip.pfx_addr);
			if (ret_val == 0)
				DPGRPC_LOG_WARNING("Invalid target prefix IP",
								   DP_LOG_PREFIX(request_.prefix().address().c_str()));
		}
		request.add_pfx.pfx_length = request_.prefix().prefixlength();
		dp_send_to_worker(&request);  // TODO can fail
		status_ = AWAIT_MSG;
		return -1;
	} else if (status_ == INITCHECK) {
		responder_.Finish(reply_, ret, this);
		status_ = FINISH;
	} else if (status_ == AWAIT_MSG) {
		if (DP_FAILED(dp_recv_from_worker(&reply, call_type_)))  // TODO can fail (this `return -1` is only a wait loop)
			return -1;
		SetErrStatus(&reply_, &reply);
		status_ = FINISH;
		responder_.Finish(reply_, ret, this);
	} else {
		GPR_ASSERT(status_ == FINISH);
		delete this;
	}
	return 0;
}

void ListLBTargetPfxCall::ListCallback(void *reply, void *context)
{
	dp_route *rp_route = (dp_route *)reply;
	ListInterfaceLoadBalancerPrefixesResponse *reply_ = (ListInterfaceLoadBalancerPrefixesResponse *)context;
	LBPrefix *pfx;
	struct in_addr addr;
	char buf_str[INET6_ADDRSTRLEN];

	pfx = reply_->add_prefixes();
	if (rp_route->pfx_ip_type == RTE_ETHER_TYPE_IPV4) {
		addr.s_addr = htonl(rp_route->pfx_ip.addr);
		pfx->set_address(inet_ntoa(addr));
		pfx->set_ipversion(dpdkonmetal::IPVersion::IPv4);
		pfx->set_prefixlength(rp_route->pfx_length);
		inet_ntop(AF_INET6, rp_route->trgt_ip.addr6, buf_str, INET6_ADDRSTRLEN);
		pfx->set_underlayroute(buf_str);
	}
	// TODO else? (should already be covered by the worker)
}

int ListLBTargetPfxCall::Proceed()
{
	dp_request request = {
		.type = call_type_,
	};

	if (status_ == REQUEST) {
		new ListLBTargetPfxCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		DPGRPC_LOG_INFO("Listing loadbalancer target prefixes",
						DP_LOG_IFACE(request_.interfaceid().c_str()));
		snprintf(request.get_pfx.machine_id, VM_MACHINE_ID_STR_LEN,
				 "%s", request_.interfaceid().c_str());
		dp_send_to_worker(&request);  // TODO can fail
		status_ = AWAIT_MSG;
		return -1;
	} else if (status_ == INITCHECK) {
		responder_.Finish(reply_, ret, this);
		status_ = FINISH;
	} else if (status_ == AWAIT_MSG) {
		// TODO can fail hard (this `return -1` is only a wait loop)
		if (DP_FAILED(dp_recv_array_from_worker(sizeof(dp_route), ListCallback, &reply_, call_type_)))
			return -1;
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
	dp_request request = {
		.type = call_type_,
	};
	dp_reply reply;
	char buf_str[INET6_ADDRSTRLEN];
	int ret_val;

	if (status_ == REQUEST) {
		new AddVIPCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		DPGRPC_LOG_INFO("Setting virtual IP",
						DP_LOG_IFACE(request_.interfaceid().c_str()),
						DP_LOG_IPV4STR(request_.interfacevipip().address().c_str()));
		snprintf(request.add_vip.machine_id, VM_MACHINE_ID_STR_LEN,
				 "%s", request_.interfaceid().c_str());
		if (request_.interfacevipip().ipversion() == dpdkonmetal::IPVersion::IPv4) {
			request.add_vip.ip_type = RTE_ETHER_TYPE_IPV4;
			ret_val = inet_aton(request_.interfacevipip().address().c_str(),
					  (in_addr*)&request.add_vip.vip.vip_addr);
			if (ret_val == 0)
				DPGRPC_LOG_WARNING("Invalid virtual IP",
								   DP_LOG_IPV4STR(request_.interfacevipip().address().c_str()));
		}
		dp_send_to_worker(&request);  // TODO can fail
		status_ = AWAIT_MSG;
		return -1;
	} else if (status_ == INITCHECK) {
		responder_.Finish(reply_, ret, this);
		status_ = FINISH;
	} else if (status_ == AWAIT_MSG) {
		if (DP_FAILED(dp_recv_from_worker(&reply, call_type_)))  // TODO can fail (this `return -1` is only a wait loop)
			return -1;
		status_ = FINISH;
		inet_ntop(AF_INET6, reply.ul_addr6, buf_str, INET6_ADDRSTRLEN);
		reply_.set_underlayroute(buf_str);
		reply_.set_allocated_status(CreateErrStatus(&reply));
		responder_.Finish(reply_, ret, this);
	} else {
		GPR_ASSERT(status_ == FINISH);
		delete this;
	}
	return 0;
}

int DelVIPCall::Proceed()
{
	dp_request request = {
		.type = call_type_,
	};
	dp_reply reply;

	if (status_ == REQUEST) {
		new DelVIPCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		DPGRPC_LOG_INFO("Removing virtual IP",
						DP_LOG_IFACE(request_.interfaceid().c_str()));
		snprintf(request.del_vip.machine_id, VM_MACHINE_ID_STR_LEN,
				 "%s", request_.interfaceid().c_str());
		dp_send_to_worker(&request);  // TODO can fail
		status_ = AWAIT_MSG;
		return -1;
	} else if (status_ == INITCHECK) {
		responder_.Finish(reply_, ret, this);
		status_ = FINISH;
	} else if (status_ == AWAIT_MSG) {
		if (DP_FAILED(dp_recv_from_worker(&reply, call_type_)))  // TODO can fail (this `return -1` is only a wait loop)
			return -1;
		status_ = FINISH;
		SetErrStatus(&reply_, &reply);
		responder_.Finish(reply_, ret, this);
	} else {
		GPR_ASSERT(status_ == FINISH);
		delete this;
	}
	return 0;
}

int GetVIPCall::Proceed()
{
	char buf_str[INET6_ADDRSTRLEN];
	dp_request request = {
		.type = call_type_,
	};
	dp_reply reply;
	struct in_addr addr;

	if (status_ == REQUEST) {
		new GetVIPCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		DPGRPC_LOG_INFO("Getting virtual IP",
						DP_LOG_IFACE(request_.interfaceid().c_str()));
		snprintf(request.get_vip.machine_id, VM_MACHINE_ID_STR_LEN,
				 "%s", request_.interfaceid().c_str());
		dp_send_to_worker(&request);  // TODO can fail
		status_ = AWAIT_MSG;
		return -1;
	} else if (status_ == INITCHECK) {
		responder_.Finish(reply_, ret, this);
		status_ = FINISH;
	} else if (status_ == AWAIT_MSG) {
		if (DP_FAILED(dp_recv_from_worker(&reply, call_type_)))  // TODO can fail (this `return -1` is only a wait loop)
			return -1;
		reply_.set_ipversion(dpdkonmetal::IPVersion::IPv4);
		addr.s_addr = reply.get_vip.vip.vip_addr;
		reply_.set_address(inet_ntoa(addr));
		inet_ntop(AF_INET6, reply.get_vip.ul_addr6, buf_str, INET6_ADDRSTRLEN);
		reply_.set_underlayroute(buf_str);
		status_ = FINISH;
		reply_.set_allocated_status(CreateErrStatus(&reply));
		responder_.Finish(reply_, ret, this);
	} else {
		GPR_ASSERT(status_ == FINISH);
		delete this;
	}
	return 0;
}

int AddInterfaceCall::Proceed()
{
	dp_request request = {
		.type = call_type_,
	};
	dp_reply reply;
	VirtualFunction *vf;
	IpAdditionResponse *ip_resp;
	char buf_str[INET6_ADDRSTRLEN];
	int ret_val;

	if (status_ == REQUEST) {
		new AddInterfaceCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		DPGRPC_LOG_INFO("Adding interface",
						DP_LOG_IFACE(request_.interfaceid().c_str()),
						DP_LOG_VNI(request_.vni()),
						DP_LOG_IPV4STR(request_.ipv4config().primaryaddress().c_str()),
						DP_LOG_IPV6STR(request_.ipv6config().primaryaddress().c_str()),
						DP_LOG_PCI(request_.devicename().c_str()));
		request.add_machine.vni = request_.vni();
		ret_val = inet_aton(request_.ipv4config().primaryaddress().c_str(),
				(in_addr*)&request.add_machine.ip4_addr);
		if (ret_val == 0)
			DPGRPC_LOG_WARNING("AddInterface: wrong primary IP",
							   DP_LOG_IPV4STR(request_.ipv4config().primaryaddress().c_str()));
		if (!request_.ipv4config().pxeconfig().nextserver().empty()) {
			DPGRPC_LOG_INFO("Setting PXE",
							DP_LOG_IFACE(request_.interfaceid().c_str()),
							DP_LOG_PXE_SRV(request_.ipv4config().pxeconfig().nextserver().c_str()),
							DP_LOG_PXE_PATH(request_.ipv4config().pxeconfig().bootfilename().c_str()));
			ret_val = inet_aton(request_.ipv4config().pxeconfig().nextserver().c_str(),
					(in_addr*)&request.add_machine.ip4_pxe_addr);
			if (ret_val == 0)
				DPGRPC_LOG_WARNING("AddInterface: wrong PXE next server IP",
								   DP_LOG_IPV4STR(request_.ipv4config().pxeconfig().nextserver().c_str()));
		}
		snprintf(request.add_machine.pxe_str, VM_MACHINE_PXE_STR_LEN, "%s",
				 request_.ipv4config().pxeconfig().bootfilename().c_str());
		snprintf(request.add_machine.name, sizeof(request.add_machine.name), "%s",
				 request_.devicename().c_str());
		ret_val = inet_pton(AF_INET6, request_.ipv6config().primaryaddress().c_str(),
								request.add_machine.ip6_addr6);
		if (ret_val <= 0)
			DPGRPC_LOG_WARNING("AddInterface: wrong IPv6 primary IP",
							   DP_LOG_IPV6STR(request_.ipv6config().primaryaddress().c_str()));
		snprintf(request.add_machine.machine_id, VM_MACHINE_ID_STR_LEN, "%s",
				 request_.interfaceid().c_str());
		dp_send_to_worker(&request);  // TODO can fail
		status_ = AWAIT_MSG;
		return -1;
	} else if (status_ == INITCHECK) {
		responder_.Finish(reply_, ret, this);
		status_ = FINISH;
	} else if (status_ == AWAIT_MSG) {
		if (DP_FAILED(dp_recv_from_worker(&reply, call_type_)))  // TODO can fail (this `return -1` is only a wait loop)
			return -1;
		vf = new VirtualFunction();
		vf->set_name(reply.vf_pci.name);
		vf->set_bus(reply.vf_pci.bus);
		vf->set_domain(reply.vf_pci.domain);
		vf->set_slot(reply.vf_pci.slot);
		vf->set_function(reply.vf_pci.function);
		reply_.set_allocated_vf(vf);
		inet_ntop(AF_INET6, reply.vf_pci.ul_addr6, buf_str, INET6_ADDRSTRLEN);
		ip_resp = new IpAdditionResponse();
		ip_resp->set_underlayroute(buf_str);
		ip_resp->set_allocated_status(CreateErrStatus(&reply));
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
	dp_request request = {
		.type = call_type_,
	};
	dp_reply reply;

	if (status_ == REQUEST) {
		new DelInterfaceCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		DPGRPC_LOG_INFO("Removing interface",
						DP_LOG_IFACE(request_.interfaceid().c_str()));
		snprintf(request.del_machine.machine_id, VM_MACHINE_ID_STR_LEN,
				 "%s", request_.interfaceid().c_str());
		dp_send_to_worker(&request);  // TODO can fail
		status_ = AWAIT_MSG;
		return -1;
	} else if (status_ == INITCHECK) {
		responder_.Finish(reply_, ret, this);
		status_ = FINISH;
	} else if (status_ == AWAIT_MSG) {
		if (DP_FAILED(dp_recv_from_worker(&reply, call_type_)))  // TODO can fail (this `return -1` is only a wait loop)
			return -1;
		SetErrStatus(&reply_, &reply);
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
	dp_request request = {
		.type = call_type_,
	};
	dp_reply reply;
	dp_vm_info *vm_info;
	Interface *machine;
	struct in_addr addr;
	char buf_str[INET6_ADDRSTRLEN];

	if (status_ == REQUEST) {
		new GetInterfaceCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		DPGRPC_LOG_INFO("Getting interface info",
						DP_LOG_IFACE(request_.interfaceid().c_str()));
		snprintf(request.get_machine.machine_id, VM_MACHINE_ID_STR_LEN,
				 "%s", request_.interfaceid().c_str());
		dp_send_to_worker(&request);  // TODO can fail
		status_ = AWAIT_MSG;
		return -1;
	} else if (status_ == INITCHECK) {
		responder_.Finish(reply_, ret, this);
		status_ = FINISH;
	} else if (status_ == AWAIT_MSG) {
		if (DP_FAILED(dp_recv_from_worker(&reply, call_type_)))  // TODO can fail (this `return -1` is only a wait loop)
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

		inet_ntop(AF_INET6, reply.vm_info.ul_addr6, buf_str, INET6_ADDRSTRLEN);
		machine->set_underlayroute(buf_str);
		reply_.set_allocated_interface(machine);
		reply_.set_allocated_status(CreateErrStatus(&reply));
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
	dp_request request = {
		.type = call_type_,
	};
	dp_reply reply;
	int ret_val;

	if (status_ == REQUEST) {
		new AddRouteCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		DPGRPC_LOG_INFO("Adding route",
						DP_LOG_VNI(request_.vni().vni()),
						DP_LOG_PREFIX(request_.route().prefix().address().c_str()),
						DP_LOG_PREFLEN(request_.route().prefix().prefixlength()),
						DP_LOG_TVNI(request_.route().nexthopvni()),
						DP_LOG_IPV6STR(request_.route().nexthopaddress().c_str()));
		request.route.vni = request_.vni().vni();
		request.route.trgt_hop_ip_type = RTE_ETHER_TYPE_IPV6;
		request.route.trgt_vni = request_.route().nexthopvni();
		ret_val = inet_pton(AF_INET6, request_.route().nexthopaddress().c_str(),
				  request.route.trgt_ip.addr6);
		if (ret_val <= 0)
			DPGRPC_LOG_WARNING("Invalid nexthop IP",
							   DP_LOG_IPV6STR(request_.route().nexthopaddress().c_str()));
		request.route.pfx_length = request_.route().prefix().prefixlength();
		if (request_.route().prefix().ipversion() == dpdkonmetal::IPVersion::IPv4) {
			request.route.pfx_ip_type = RTE_ETHER_TYPE_IPV4;
			ret_val = inet_aton(request_.route().prefix().address().c_str(),
					(in_addr*)&request.route.pfx_ip.addr);
			if (ret_val == 0)
				DPGRPC_LOG_WARNING("Invalid prefix IP",
								   DP_LOG_PREFIX(request_.route().prefix().address().c_str()));
		} else {
			request.route.pfx_ip_type = RTE_ETHER_TYPE_IPV6;
			ret_val = inet_pton(AF_INET6, request_.route().prefix().address().c_str(),
					request.route.pfx_ip.addr6);
			if (ret_val <= 0)
				DPGRPC_LOG_WARNING("Invalid prefix IP",
								   DP_LOG_PREFIX(request_.route().prefix().address().c_str()));
		}
		dp_send_to_worker(&request);  // TODO can fail
		status_ = AWAIT_MSG;
		return -1;
	} else if (status_ == INITCHECK) {
		responder_.Finish(reply_, ret, this);
		status_ = FINISH;
	} else if (status_ == AWAIT_MSG) {
		if (DP_FAILED(dp_recv_from_worker(&reply, call_type_)))  // TODO can fail (this `return -1` is only a wait loop)
			return -1;
		SetErrStatus(&reply_, &reply);
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
	dp_request request = {
		.type = call_type_,
	};
	dp_reply reply;
	int ret_val;

	if (status_ == REQUEST) {
		new DelRouteCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		DPGRPC_LOG_INFO("Removing route",
						DP_LOG_VNI(request_.vni().vni()),
						DP_LOG_PREFIX(request_.route().prefix().address().c_str()),
						DP_LOG_PREFLEN(request_.route().prefix().prefixlength()),
						DP_LOG_TVNI(request_.route().nexthopvni()), // TODO re-check for target vni everywhere
						DP_LOG_IPV6STR(request_.route().nexthopaddress().c_str()));
		request.route.vni = request_.vni().vni();
		request.route.trgt_hop_ip_type = RTE_ETHER_TYPE_IPV6;
		request.route.trgt_vni = request_.route().nexthopvni();
		if (!request_.route().nexthopaddress().empty()) {
			ret_val = inet_pton(AF_INET6, request_.route().nexthopaddress().c_str(),
					request.route.trgt_ip.addr6);
			if (ret_val <= 0)
				DPGRPC_LOG_WARNING("Invalid nexthop IP",
								   DP_LOG_IPV6STR(request_.route().nexthopaddress().c_str()));
		}
		request.route.pfx_length = request_.route().prefix().prefixlength();
		if (request_.route().prefix().ipversion() == dpdkonmetal::IPVersion::IPv4) {
			request.route.pfx_ip_type = RTE_ETHER_TYPE_IPV4;
			ret_val = inet_aton(request_.route().prefix().address().c_str(),
					(in_addr*)&request.route.pfx_ip.addr);
			if (ret_val == 0)
				DPGRPC_LOG_WARNING("Invalid prefix IP",
								   DP_LOG_PREFIX(request_.route().prefix().address().c_str()));
		} else {
			request.route.pfx_ip_type = RTE_ETHER_TYPE_IPV6;
			ret_val = inet_pton(AF_INET6, request_.route().prefix().address().c_str(),
					request.route.pfx_ip.addr6);
			if (ret_val <= 0)
				DPGRPC_LOG_WARNING("Invalid prefix IP",
								   DP_LOG_PREFIX(request_.route().prefix().address().c_str()));
		}
		dp_send_to_worker(&request);  // TODO can fail
		status_ = AWAIT_MSG;
		return -1;
	} else if (status_ == INITCHECK) {
		responder_.Finish(reply_, ret, this);
		status_ = FINISH;
	} else if (status_ == AWAIT_MSG) {
		if (DP_FAILED(dp_recv_from_worker(&reply, call_type_)))  // TODO can fail (this `return -1` is only a wait loop)
			return -1;
		SetErrStatus(&reply_, &reply);
		status_ = FINISH;
		responder_.Finish(reply_, ret, this);
	} else {
		GPR_ASSERT(status_ == FINISH);
		delete this;
	}
	return 0;
}

void ListRoutesCall::ListCallback(void *reply, void *context)
{
	dp_route *rp_route = (dp_route *)reply;
	RoutesMsg *reply_ = (RoutesMsg *)context;
	Route *route;
	struct in_addr addr;
	Prefix *pfx;
	char buf[INET6_ADDRSTRLEN];

	route = reply_->add_routes();
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

int ListRoutesCall::Proceed()
{
	dp_request request = {
		.type = call_type_,
	};

	if (status_ == REQUEST) {
		new ListRoutesCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		DPGRPC_LOG_INFO("Listing routes",
						DP_LOG_VNI(request_.vni()));
		request.route.vni = request_.vni();
		dp_send_to_worker(&request);  // TODO can fail
		status_ = AWAIT_MSG;
		return -1;
	} else if (status_ == INITCHECK) {
		responder_.Finish(reply_, ret, this);
		status_ = FINISH;
	} else if (status_ == AWAIT_MSG) {
		// TODO can fail hard (this `return -1` is only a wait loop)
		if (DP_FAILED(dp_recv_array_from_worker(sizeof(dp_route), ListCallback, &reply_, call_type_)))
			return -1;
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
	dp_request request = {
		.type = call_type_,
	};
	dp_reply reply;

	grpc::Status ret = grpc::Status::OK;
	char buf_str[INET6_ADDRSTRLEN];
	int ret_val;

	if (status_ == REQUEST) {
		new AddNATVIPCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		DPGRPC_LOG_INFO("Setting NAT IP",
						DP_LOG_IFACE(request_.interfaceid().c_str()),
						DP_LOG_IPV4STR(request_.natvipip().address().c_str()),
						DP_LOG_MINPORT(request_.minport()),
						DP_LOG_MAXPORT(request_.maxport()));
		snprintf(request.add_nat_vip.machine_id, VM_MACHINE_ID_STR_LEN,
				 "%s", request_.interfaceid().c_str());
		if (request_.natvipip().ipversion() == dpdkonmetal::IPVersion::IPv4) {
			request.add_nat_vip.ip_type = RTE_ETHER_TYPE_IPV4;
			ret_val = inet_aton(request_.natvipip().address().c_str(),
					  (in_addr*)&request.add_nat_vip.vip.vip_addr);
			if (ret_val == 0)
				DPGRPC_LOG_WARNING("Invalid NAT IP",
								   DP_LOG_IPV4STR(request_.natvipip().address().c_str()));
		}

		// maybe add a validity check here to ensure minport is not greater than 2^30
		request.add_nat_vip.port_range[0] = request_.minport();
		request.add_nat_vip.port_range[1] = request_.maxport();

		dp_send_to_worker(&request);  // TODO can fail
		status_ = AWAIT_MSG;
		return -1;
	} else if (status_ == INITCHECK) {
		responder_.Finish(reply_, ret, this);
		status_ = FINISH;
	} else if (status_ == AWAIT_MSG) {
		if (DP_FAILED(dp_recv_from_worker(&reply, call_type_)))  // TODO can fail (this `return -1` is only a wait loop)
			return -1;
		status_ = FINISH;
		inet_ntop(AF_INET6, reply.ul_addr6, buf_str, INET6_ADDRSTRLEN);
		reply_.set_underlayroute(buf_str);
		reply_.set_allocated_status(CreateErrStatus(&reply));
		responder_.Finish(reply_, ret, this);
	} else {
		GPR_ASSERT(status_ == FINISH);
		delete this;
	}
	return 0;
}

int GetNATVIPCall::Proceed()
{
	dp_request request = {
		.type = call_type_,
	};
	dp_reply reply;
	struct in_addr addr;
	NATIP *nat_ip;
	char buf[INET6_ADDRSTRLEN];

	if (status_ == REQUEST) {
		new GetNATVIPCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		DPGRPC_LOG_INFO("Getting NAT IP",
						DP_LOG_IFACE(request_.interfaceid().c_str()));
		snprintf(request.get_vip.machine_id, VM_MACHINE_ID_STR_LEN,
				 "%s", request_.interfaceid().c_str());
		dp_send_to_worker(&request);  // TODO can fail
		status_ = AWAIT_MSG;
		return -1;
	} else if (status_ == INITCHECK) {
		responder_.Finish(reply_, ret, this);
		status_ = FINISH;
	} else if (status_ == AWAIT_MSG) {
		if (DP_FAILED(dp_recv_from_worker(&reply, call_type_)))  // TODO can fail (this `return -1` is only a wait loop)
			return -1;
		nat_ip = new NATIP();
		addr.s_addr = reply.nat_entry.m_ip.addr;
		nat_ip->set_address(inet_ntoa(addr));
		nat_ip->set_ipversion(dpdkonmetal::IPVersion::IPv4);
		reply_.set_allocated_natvipip(nat_ip);
		reply_.set_maxport(reply.nat_entry.max_port);
		reply_.set_minport(reply.nat_entry.min_port);
		inet_ntop(AF_INET6, reply.nat_entry.underlay_route, buf, INET6_ADDRSTRLEN);
		reply_.set_underlayroute(buf);
		status_ = FINISH;
		reply_.set_allocated_status(CreateErrStatus(&reply));
		responder_.Finish(reply_, ret, this);
	} else {
		GPR_ASSERT(status_ == FINISH);
		delete this;
	}
	return 0;
}

int DeleteNATVIPCall::Proceed()
{
	dp_request request = {
		.type = call_type_,
	};
	dp_reply reply;
	grpc::Status ret = grpc::Status::OK;

	if (status_ == REQUEST) {
		new DeleteNATVIPCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		DPGRPC_LOG_INFO("Removing NAT IP",
						DP_LOG_IFACE(request_.interfaceid().c_str()));
		snprintf(request.del_nat_vip.machine_id, VM_MACHINE_ID_STR_LEN,
				 "%s", request_.interfaceid().c_str());
		dp_send_to_worker(&request);  // TODO can fail
		status_ = AWAIT_MSG;
		return -1;
	} else if (status_ == INITCHECK) {
		responder_.Finish(reply_, ret, this);
		status_ = FINISH;
	}
	else if (status_ == AWAIT_MSG) {
		if (DP_FAILED(dp_recv_from_worker(&reply, call_type_)))  // TODO can fail (this `return -1` is only a wait loop)
			return -1;
		status_ = FINISH;
		SetErrStatus(&reply_, &reply);
		responder_.Finish(reply_, ret, this);
	} else {
		GPR_ASSERT(status_ == FINISH);
		delete this;
	}
	return 0;
}

int AddNeighborNATCall::Proceed()
{
	dp_request request = {
		.type = call_type_,
	};
	dp_reply reply;
	int ret_val;
	grpc::Status ret = grpc::Status::OK;

	if (status_ == REQUEST) {
		new AddNeighborNATCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		DPGRPC_LOG_INFO("Adding neighboring NAT",
						DP_LOG_VNI(request_.vni()),
						DP_LOG_IPV4STR(request_.natvipip().address().c_str()),
						DP_LOG_MINPORT(request_.minport()),
						DP_LOG_MAXPORT(request_.maxport()),
						DP_LOG_IPV6STR(request_.underlayroute().c_str()));
		request.add_nat_neigh.type = DP_NETNAT_INFO_TYPE_NEIGHBOR;
		if (request_.natvipip().ipversion() == dpdkonmetal::IPVersion::IPv4) {
			request.add_nat_neigh.ip_type = RTE_ETHER_TYPE_IPV4;
			ret_val = inet_aton(request_.natvipip().address().c_str(),
					  (in_addr*)&request.add_nat_neigh.vip.vip_addr);
			if (ret_val == 0)
				DPGRPC_LOG_WARNING("Invalid NAT IP",
								   DP_LOG_IPV4STR(request_.natvipip().address().c_str()));
		}
		// FIXME adding ipv6 will break this

		// maybe add a validity check here to ensure minport is not greater than 2^30
		request.add_nat_neigh.vni = request_.vni();
		request.add_nat_neigh.port_range[0] = request_.minport();
		request.add_nat_neigh.port_range[1] = request_.maxport();
		ret_val = inet_pton(AF_INET6, request_.underlayroute().c_str(),
				request.add_nat_neigh.route);
		if (ret_val <= 0)
			DPGRPC_LOG_WARNING("Invalid underlay IP",
							   DP_LOG_IPV6STR(request_.underlayroute().c_str()));
		dp_send_to_worker(&request);  // TODO can fail
		status_ = AWAIT_MSG;
		return -1;
	} else if (status_ == INITCHECK) {
		responder_.Finish(reply_, ret, this);
		status_ = FINISH;
	} else if (status_ == AWAIT_MSG) {
		if (DP_FAILED(dp_recv_from_worker(&reply, call_type_)))  // TODO can fail (this `return -1` is only a wait loop)
			return -1;
		status_ = FINISH;
		SetErrStatus(&reply_, &reply);
		responder_.Finish(reply_, ret, this);
	} else {
		GPR_ASSERT(status_ == FINISH);
		delete this;
	}
	return 0;

}

int DeleteNeighborNATCall::Proceed()
{
	dp_request request = {
		.type = call_type_,
	};
	dp_reply reply;
	grpc::Status ret = grpc::Status::OK;
	int ret_val;

	if (status_ == REQUEST) {
		new DeleteNeighborNATCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		DPGRPC_LOG_INFO("Removing neighboring NAT",
						DP_LOG_VNI(request_.vni()),
						DP_LOG_IPV4STR(request_.natvipip().address().c_str()),
						DP_LOG_MINPORT(request_.minport()),
						DP_LOG_MAXPORT(request_.maxport()));
		request.del_nat_neigh.type = DP_NETNAT_INFO_TYPE_NEIGHBOR;

		if (request_.natvipip().ipversion() == dpdkonmetal::IPVersion::IPv4) {
			request.del_nat_neigh.ip_type = RTE_ETHER_TYPE_IPV4;
			ret_val = inet_aton(request_.natvipip().address().c_str(),
					  (in_addr*)&request.del_nat_neigh.vip.vip_addr);
			if (ret_val == 0)
				DPGRPC_LOG_WARNING("Invalid NAT IP",
								   DP_LOG_IPV4STR(request_.natvipip().address().c_str()));
		}

		// maybe add a validity check here to ensure minport is not greater than 2^30
		request.del_nat_neigh.vni = request_.vni();
		request.del_nat_neigh.port_range[0] = request_.minport();
		request.del_nat_neigh.port_range[1] = request_.maxport();

		dp_send_to_worker(&request);  // TODO can fail
		status_ = AWAIT_MSG;
		return -1;
	} else if (status_ == INITCHECK) {
		responder_.Finish(reply_, ret, this);
		status_ = FINISH;
	} else if (status_ == AWAIT_MSG) {
		if (DP_FAILED(dp_recv_from_worker(&reply, call_type_)))  // TODO can fail (this `return -1` is only a wait loop)
			return -1;
		status_ = FINISH;
		SetErrStatus(&reply_, &reply);
		responder_.Finish(reply_, ret, this);
	} else {
		GPR_ASSERT(status_ == FINISH);
		delete this;
	}
	return 0;
}

void ListInterfacesCall::ListCallback(void *reply, void *context)
{
	dp_vm_info *vm_info = (dp_vm_info *)reply;
	InterfacesMsg *reply_ = (InterfacesMsg *)context;
	Interface *machine;
	struct in_addr addr;
	char buf_str[INET6_ADDRSTRLEN];

	machine = reply_->add_interfaces();
	addr.s_addr = htonl(vm_info->ip_addr);
	machine->set_primaryipv4address(inet_ntoa(addr));
	inet_ntop(AF_INET6, vm_info->ip6_addr, buf_str, INET6_ADDRSTRLEN);
	machine->set_primaryipv6address(buf_str);
	machine->set_interfaceid((char *)vm_info->machine_id);
	machine->set_vni(vm_info->vni);
	machine->set_pcidpname(vm_info->pci_name);
	inet_ntop(AF_INET6, vm_info->ul_addr6, buf_str, INET6_ADDRSTRLEN);
	machine->set_underlayroute(buf_str);
}

int ListInterfacesCall::Proceed()
{
	dp_request request = {
		.type = call_type_,
	};

	if (status_ == REQUEST) {
		new ListInterfacesCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		DPGRPC_LOG_INFO("Listing interfaces");
		dp_send_to_worker(&request);  // TODO can fail
		status_ = AWAIT_MSG;
		return -1;
	} else if (status_ == INITCHECK) {
		responder_.Finish(reply_, ret, this);
		status_ = FINISH;
	} else if (status_ == AWAIT_MSG) {
		// TODO can fail hard (this `return -1` is only a wait loop)
		if (DP_FAILED(dp_recv_array_from_worker(sizeof(dp_vm_info), ListCallback, &reply_, call_type_)))
			return -1;
		status_ = FINISH;
		responder_.Finish(reply_, ret, this);
	} else {
		GPR_ASSERT(status_ == FINISH);
		delete this;
	}
	return 0;
}

void GetNATInfoCall::ListCallbackLocal(void *reply, void *context)
{
	dp_nat_entry *nat_entry = (dp_nat_entry *)reply;
	GetNATInfoResponse *reply_ = (GetNATInfoResponse *)context;
	NATInfoEntry *rep_nat_entry;
	struct in_addr addr;

	rep_nat_entry = reply_->add_natinfoentries();
	addr.s_addr = htonl(nat_entry->m_ip.addr);
	rep_nat_entry->set_ipversion(dpdkonmetal::IPVersion::IPv4);
	rep_nat_entry->set_address(inet_ntoa(addr));
	rep_nat_entry->set_minport(nat_entry->min_port);
	rep_nat_entry->set_maxport(nat_entry->max_port);
}

void GetNATInfoCall::ListCallbackNeigh(void *reply, void *context)
{
	dp_nat_entry *nat_entry = (dp_nat_entry *)reply;
	GetNATInfoResponse *reply_ = (GetNATInfoResponse *)context;
	NATInfoEntry *rep_nat_entry;
	char buf[INET6_ADDRSTRLEN];

	rep_nat_entry = reply_->add_natinfoentries();
	inet_ntop(AF_INET6, nat_entry->underlay_route, buf, INET6_ADDRSTRLEN);
	rep_nat_entry->set_underlayroute(buf);
	rep_nat_entry->set_minport(nat_entry->min_port);
	rep_nat_entry->set_maxport(nat_entry->max_port);
}

int GetNATInfoCall::Proceed()
{
	dp_request request = {
		.type = call_type_,
	};
	NATIP *nat_ip;
	dp_recv_array_callback list_callback;
	int ret_val;

	if (status_ == REQUEST) {
		new GetNATInfoCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		DPGRPC_LOG_INFO("Getting NAT info",
						DP_LOG_NATINFOTYPE(request_.natinfotype()),
						DP_LOG_IPV4STR(request_.natvipip().address().c_str()));

		if (request_.natinfotype() == dpdkonmetal::NATInfoType::NATInfoLocal)
			request.get_nat_entry.type = DP_NETNAT_INFO_TYPE_LOCAL;
		else if (request_.natinfotype() == dpdkonmetal::NATInfoType::NATInfoNeigh)
			request.get_nat_entry.type = DP_NETNAT_INFO_TYPE_NEIGHBOR;
		// FIXME else enter infinite wait in caller

		if (request_.natvipip().ipversion() == dpdkonmetal::IPVersion::IPv4) {
			request.get_nat_entry.ip_type = RTE_ETHER_TYPE_IPV4;
			ret_val = inet_aton(request_.natvipip().address().c_str(),
					  (in_addr*)&request.get_nat_entry.vip.vip_addr);
			if (ret_val == 0)
				DPGRPC_LOG_WARNING("Invalid NAT IP",
								   DP_LOG_IPV4STR(request_.natvipip().address().c_str()));
		}
		dp_send_to_worker(&request);  // TODO can fail
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
		if (request_.natinfotype() == dpdkonmetal::NATInfoType::NATInfoLocal)
			list_callback = ListCallbackLocal;
		else if (request_.natinfotype() == dpdkonmetal::NATInfoType::NATInfoNeigh)
			list_callback = ListCallbackNeigh;
		// TODO else invalid type (but that is already covered by the worker...)
		// TODO can fail hard (this `return -1` is only a wait loop)
		if (DP_FAILED(dp_recv_array_from_worker(sizeof(dp_nat_entry), list_callback, &reply_, call_type_)))
			return -1;
		status_ = FINISH;
		responder_.Finish(reply_, ret, this);
	} else {
		GPR_ASSERT(status_ == FINISH);
		delete this;
	}
	return 0;
}

int AddFirewallRuleCall::Proceed()
{
	dp_request request = {
		.type = call_type_,
	};
	dp_reply reply;
	const FirewallRule *grpc_rule;

	if (status_ == REQUEST) {
		new AddFirewallRuleCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		grpc_rule = &request_.rule();
		DPGRPC_LOG_INFO("Adding firewall rule",
						DP_LOG_IFACE(request_.interfaceid().c_str()),
						DP_LOG_FWRULE(grpc_rule->ruleid().c_str()),
						DP_LOG_FWPRIO(grpc_rule->priority()),
						DP_LOG_FWDIR(grpc_rule->direction()),
						DP_LOG_FWACTION(grpc_rule->action()),
						DP_LOG_FWSRC(grpc_rule->sourceprefix().address().c_str()),
						DP_LOG_FWSRCLEN(grpc_rule->sourceprefix().prefixlength()),
						DP_LOG_FWDST(grpc_rule->destinationprefix().address().c_str()),
						DP_LOG_FWDSTLEN(grpc_rule->destinationprefix().prefixlength()));
		snprintf(request.fw_rule.machine_id, VM_MACHINE_ID_STR_LEN,
				 "%s", request_.interfaceid().c_str());
		ConvertGRPCFwallRuleToDPFWallRule(grpc_rule, &request.fw_rule.rule);
		dp_send_to_worker(&request);  // TODO can fail
		status_ = AWAIT_MSG;
		return -1;
	} else if (status_ == INITCHECK) {
		responder_.Finish(reply_, ret, this);
		status_ = FINISH;
	} else if (status_ == AWAIT_MSG) {
		if (DP_FAILED(dp_recv_from_worker(&reply, call_type_)))  // TODO can fail (this `return -1` is only a wait loop)
			return -1;
		status_ = FINISH;
		reply_.set_allocated_status(CreateErrStatus(&reply));
		reply_.set_ruleid(&reply.fwall_rule.rule_id, sizeof(reply.fwall_rule.rule_id));
		responder_.Finish(reply_, ret, this);
	} else {
		GPR_ASSERT(status_ == FINISH);
		delete this;
	}
	return 0;
}

int DelFirewallRuleCall::Proceed()
{
	dp_request request = {
		.type = call_type_,
	};
	dp_reply reply;

	if (status_ == REQUEST) {
		new DelFirewallRuleCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		DPGRPC_LOG_INFO("Removing firewall rule",
						DP_LOG_IFACE(request_.interfaceid().c_str()),
						DP_LOG_FWRULE(request_.ruleid().c_str()));
		snprintf(request.fw_rule.machine_id, VM_MACHINE_ID_STR_LEN,
				 "%s", request_.interfaceid().c_str());
		snprintf(request.fw_rule.rule.rule_id, DP_FIREWALL_ID_STR_LEN,
				 "%s", request_.ruleid().c_str());
		dp_send_to_worker(&request);  // TODO can fail
		status_ = AWAIT_MSG;
		return -1;
	} else if (status_ == INITCHECK) {
		responder_.Finish(reply_, ret, this);
		status_ = FINISH;
	} else if (status_ == AWAIT_MSG) {
		if (DP_FAILED(dp_recv_from_worker(&reply, call_type_)))  // TODO can fail (this `return -1` is only a wait loop)
			return -1;
		status_ = FINISH;
		SetErrStatus(&reply_, &reply);
		responder_.Finish(reply_, ret, this);
	} else {
		GPR_ASSERT(status_ == FINISH);
		delete this;
	}
	return 0;
}

int GetFirewallRuleCall::Proceed()
{
	dp_request request = {
		.type = call_type_,
	};
	dp_reply reply;
	FirewallRule *rule;

	if (status_ == REQUEST) {
		new GetFirewallRuleCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		DPGRPC_LOG_INFO("Getting firewall rule info",
						DP_LOG_IFACE(request_.interfaceid().c_str()),
						DP_LOG_FWRULE(request_.ruleid().c_str()));
		snprintf(request.fw_rule.machine_id, VM_MACHINE_ID_STR_LEN,
				 "%s", request_.interfaceid().c_str());
		snprintf(request.fw_rule.rule.rule_id, DP_FIREWALL_ID_STR_LEN,
				 "%s", request_.ruleid().c_str());
		dp_send_to_worker(&request);  // TODO can fail
		status_ = AWAIT_MSG;
		return -1;
	} else if (status_ == INITCHECK) {
		responder_.Finish(reply_, ret, this);
		status_ = FINISH;
	} else if (status_ == AWAIT_MSG) {
		if (DP_FAILED(dp_recv_from_worker(&reply, call_type_)))  // TODO can fail (this `return -1` is only a wait loop)
			return -1;

		rule = new FirewallRule();
		ConvertDPFWallRuleToGRPCFwallRule(&reply.fwall_rule, rule);
		reply_.set_allocated_rule(rule);

		status_ = FINISH;
		reply_.set_allocated_status(CreateErrStatus(&reply));
		responder_.Finish(reply_, ret, this);
	} else {
		GPR_ASSERT(status_ == FINISH);
		delete this;
	}
	return 0;
}

void ListFirewallRulesCall::ListCallback(void *reply, void *context)
{
	struct dp_fwall_rule *dp_rule = (struct dp_fwall_rule *)reply;
	ListFirewallRulesResponse *reply_ = (ListFirewallRulesResponse *)context;
	FirewallRule *rule;

	rule = reply_->add_rules();
	ConvertDPFWallRuleToGRPCFwallRule(dp_rule, rule);
}

int ListFirewallRulesCall::Proceed()
{
	dp_request request = {
		.type = call_type_,
	};

	if (status_ == REQUEST) {
		new ListFirewallRulesCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		DPGRPC_LOG_INFO("Listing firewall rules",
						DP_LOG_IFACE(request_.interfaceid().c_str()));
		snprintf(request.fw_rule.machine_id, VM_MACHINE_ID_STR_LEN,
				 "%s", request_.interfaceid().c_str());
		dp_send_to_worker(&request);  // TODO can fail
		status_ = AWAIT_MSG;
		return -1;
	} else if (status_ == INITCHECK) {
		responder_.Finish(reply_, ret, this);
		status_ = FINISH;
	} else if (status_ == AWAIT_MSG) {
		// TODO can fail hard (this `return -1` is only a wait loop)
		if (DP_FAILED(dp_recv_array_from_worker(sizeof(struct dp_fwall_rule), ListCallback, &reply_, call_type_)))
			return -1;
		status_ = FINISH;
		responder_.Finish(reply_, ret, this);
	} else {
		GPR_ASSERT(status_ == FINISH);
		delete this;
	}
	return 0;
}
