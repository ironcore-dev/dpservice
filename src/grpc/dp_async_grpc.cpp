#include "grpc/dp_async_grpc.h"
#include <arpa/inet.h>
#include <rte_ether.h>
#include <rte_mbuf.h>
#include "dp_log.h"
#include "dp_lpm.h"
#include "dp_util.h"
#include "grpc/dp_grpc_queue.h"
#include "grpc/dp_grpc_service.h"

// TODO(plague): this should all get wrapped in a superclass
#define DPGRPC_GET_MESSAGE(REPLY, I, TYPE) (TYPE *)((REPLY)->messages + (I) * sizeof(TYPE))

inline Status *BaseCall::CreateErrStatus(dpgrpc_reply *reply) {
	uint32_t err_code = reply->err_code;
	Status *err_status = new Status();
	err_status->set_code(err_code);
	err_status->set_message(dp_grpc_strerror(err_code));
	return err_status;
}

void BaseCall::ConvertGRPCFwallRuleToDPFWallRule(const FirewallRule *grpc_rule, struct dp_fwall_rule *dp_rule)
{
	int ret_val;

	snprintf(dp_rule->rule_id, sizeof(dp_rule->rule_id),
				"%s", grpc_rule->id().c_str());
	if (grpc_rule->source_prefix().ipver() == IPVersion::IPV4) {
		ret_val = inet_aton(grpc_rule->source_prefix().address().c_str(),
					(in_addr*)&dp_rule->src_ip);
		if (ret_val == 0)
			DPGRPC_LOG_WARNING("Bad firewall rule, wrong source prefix address",
							   DP_LOG_FWRULE(grpc_rule->id().c_str()),
							   DP_LOG_FWSRC(grpc_rule->source_prefix().address().c_str()));
		if (grpc_rule->source_prefix().length() != DP_FWALL_MATCH_ANY_LENGTH)
			dp_rule->src_ip_mask = ~((1 << (32 - grpc_rule->source_prefix().length())) - 1);
		else
			dp_rule->src_ip_mask = DP_FWALL_MATCH_ANY_LENGTH;
	}

	if (grpc_rule->destination_prefix().ipver() == IPVersion::IPV4) {
		ret_val = inet_aton(grpc_rule->destination_prefix().address().c_str(),
					(in_addr*)&dp_rule->dest_ip);
		if (ret_val == 0)
			DPGRPC_LOG_WARNING("Bad firewall rule, wrong destination prefix address",
							   DP_LOG_FWRULE(grpc_rule->id().c_str()),
							   DP_LOG_FWSRC(grpc_rule->destination_prefix().address().c_str()));
		if (grpc_rule->destination_prefix().length() != DP_FWALL_MATCH_ANY_LENGTH)
			dp_rule->dest_ip_mask = ~((1 << (32 - grpc_rule->destination_prefix().length())) - 1);
		else
			dp_rule->dest_ip_mask = DP_FWALL_MATCH_ANY_LENGTH;
	}

	if (grpc_rule->direction() == TrafficDirection::INGRESS)
		dp_rule->dir = DP_FWALL_INGRESS;
	else
		dp_rule->dir = DP_FWALL_EGRESS;

	if (grpc_rule->action() == FirewallAction::ACCEPT)
		dp_rule->action = DP_FWALL_ACCEPT;
	else
		dp_rule->action = DP_FWALL_DROP;

	dp_rule->priority = grpc_rule->priority();

	switch (grpc_rule->protocol_filter().filter_case()) {
		case ProtocolFilter::kTcpFieldNumber:
			dp_rule->protocol = IPPROTO_TCP;
			dp_rule->filter.tcp_udp.src_port.lower = grpc_rule->protocol_filter().tcp().src_port_lower();
			dp_rule->filter.tcp_udp.dst_port.lower = grpc_rule->protocol_filter().tcp().dst_port_lower();
			dp_rule->filter.tcp_udp.src_port.upper = grpc_rule->protocol_filter().tcp().src_port_upper();
			dp_rule->filter.tcp_udp.dst_port.upper = grpc_rule->protocol_filter().tcp().dst_port_upper();
			DPGRPC_LOG_INFO("Adding firewall rule filter",
							DP_LOG_FWRULE(grpc_rule->id().c_str()),
							DP_LOG_FWPROTO(dp_rule->protocol),
							DP_LOG_FWSPORTFROM(dp_rule->filter.tcp_udp.src_port.lower),
							DP_LOG_FWSPORTTO(dp_rule->filter.tcp_udp.src_port.upper),
							DP_LOG_FWDPORTFROM(dp_rule->filter.tcp_udp.dst_port.lower),
							DP_LOG_FWDPORTTO(dp_rule->filter.tcp_udp.dst_port.upper));
		break;
		case ProtocolFilter::kUdpFieldNumber:
			dp_rule->protocol = IPPROTO_UDP;
			dp_rule->filter.tcp_udp.src_port.lower = grpc_rule->protocol_filter().udp().src_port_lower();
			dp_rule->filter.tcp_udp.dst_port.lower = grpc_rule->protocol_filter().udp().dst_port_lower();
			dp_rule->filter.tcp_udp.src_port.upper = grpc_rule->protocol_filter().udp().src_port_upper();
			dp_rule->filter.tcp_udp.dst_port.upper = grpc_rule->protocol_filter().udp().dst_port_upper();
			DPGRPC_LOG_INFO("Adding firewall rule filter",
							DP_LOG_FWRULE(grpc_rule->id().c_str()),
							DP_LOG_FWPROTO(dp_rule->protocol),
							DP_LOG_FWSPORTFROM(dp_rule->filter.tcp_udp.src_port.lower),
							DP_LOG_FWSPORTTO(dp_rule->filter.tcp_udp.src_port.upper),
							DP_LOG_FWDPORTFROM(dp_rule->filter.tcp_udp.dst_port.lower),
							DP_LOG_FWDPORTTO(dp_rule->filter.tcp_udp.dst_port.upper));
		break;
		case ProtocolFilter::kIcmpFieldNumber:
			dp_rule->protocol = IPPROTO_ICMP;
			dp_rule->filter.icmp.icmp_type = grpc_rule->protocol_filter().icmp().icmp_type();
			dp_rule->filter.icmp.icmp_code = grpc_rule->protocol_filter().icmp().icmp_code();
			DPGRPC_LOG_INFO("Adding firewall rule filter",
							DP_LOG_FWRULE(grpc_rule->id().c_str()),
							DP_LOG_FWPROTO(dp_rule->protocol),
							DP_LOG_FWICMPTYPE(dp_rule->filter.icmp.icmp_type),
							DP_LOG_FWICMPCODE(dp_rule->filter.icmp.icmp_code));
		break;
		case ProtocolFilter::FILTER_NOT_SET:
		default:
			dp_rule->protocol = DP_FWALL_MATCH_ANY_PROTOCOL;
			dp_rule->filter.tcp_udp.src_port.lower = DP_FWALL_MATCH_ANY_PORT;
			dp_rule->filter.tcp_udp.dst_port.lower = DP_FWALL_MATCH_ANY_PORT;
			DPGRPC_LOG_INFO("Adding firewall rule filter",
							DP_LOG_FWRULE(grpc_rule->id().c_str()),
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

	grpc_rule->set_id(dp_rule->rule_id);
	grpc_rule->set_ipver(IPVersion::IPV4);
	grpc_rule->set_priority(dp_rule->priority);
	if (dp_rule->dir == DP_FWALL_INGRESS)
		grpc_rule->set_direction(TrafficDirection::INGRESS);
	else
		grpc_rule->set_direction(TrafficDirection::EGRESS);

	if (dp_rule->action == DP_FWALL_ACCEPT)
		grpc_rule->set_action(FirewallAction::ACCEPT);
	else
		grpc_rule->set_action(FirewallAction::DROP);

	src_ip = new Prefix();
	src_ip->set_ipver(IPVersion::IPV4);
	addr.s_addr = dp_rule->src_ip;
	src_ip->set_address(inet_ntoa(addr));
	src_ip->set_length(__builtin_popcount(dp_rule->src_ip_mask));
	grpc_rule->set_allocated_source_prefix(src_ip);

	dst_ip = new Prefix();
	dst_ip->set_ipver(IPVersion::IPV4);
	addr.s_addr = dp_rule->dest_ip;
	dst_ip->set_address(inet_ntoa(addr));
	dst_ip->set_length(__builtin_popcount(dp_rule->dest_ip_mask));
	grpc_rule->set_allocated_destination_prefix(dst_ip);

	filter = new ProtocolFilter();
	if (dp_rule->protocol == IPPROTO_TCP) {
		tcp_filter = new TCPFilter();
		tcp_filter->set_dst_port_lower(dp_rule->filter.tcp_udp.dst_port.lower);
		tcp_filter->set_dst_port_upper(dp_rule->filter.tcp_udp.dst_port.upper);
		tcp_filter->set_src_port_lower(dp_rule->filter.tcp_udp.src_port.lower);
		tcp_filter->set_src_port_upper(dp_rule->filter.tcp_udp.src_port.upper);
		filter->set_allocated_tcp(tcp_filter);
		grpc_rule->set_allocated_protocol_filter(filter);
	}
	if (dp_rule->protocol == IPPROTO_UDP) {
		udp_filter = new UDPFilter();
		udp_filter->set_dst_port_lower(dp_rule->filter.tcp_udp.dst_port.lower);
		udp_filter->set_dst_port_upper(dp_rule->filter.tcp_udp.dst_port.upper);
		udp_filter->set_src_port_lower(dp_rule->filter.tcp_udp.src_port.lower);
		udp_filter->set_src_port_upper(dp_rule->filter.tcp_udp.src_port.upper);
		filter->set_allocated_udp(udp_filter);
		grpc_rule->set_allocated_protocol_filter(filter);
	}
	if (dp_rule->protocol == IPPROTO_ICMP) {
		icmp_filter = new ICMPFilter();
		icmp_filter->set_icmp_code(dp_rule->filter.icmp.icmp_code);
		icmp_filter->set_icmp_type(dp_rule->filter.icmp.icmp_type);
		filter->set_allocated_icmp(icmp_filter);
		grpc_rule->set_allocated_protocol_filter(filter);
	}
}

int CheckVniInUseCall::Proceed()
{
	struct dpgrpc_request request = {
		.type = call_type_,
	};
	struct dpgrpc_reply reply;

	if (status_ == REQUEST) {
		new CheckVniInUseCall(service_, cq_);
		switch (request_.type()) {
		case VniType::VNI_IPV4:
			request.vni_in_use.type = DP_VNI_IPV4;
			break;
		case VniType::VNI_IPV6:
			request.vni_in_use.type = DP_VNI_IPV6;
			break;
		// TODO(guvenc,plague): is this wanted? requesting both gives only one
		default:
			request.vni_in_use.type = DP_VNI_IPV4;
			break;
		}
		request.vni_in_use.vni = request_.vni();
		DPGRPC_LOG_DEBUG("Checking VNI usage", DP_LOG_VNI(request.vni_in_use.vni),
						DP_LOG_VNI_TYPE(request.vni_in_use.type));
		dp_send_to_worker(&request);  // TODO can fail
		status_ = AWAIT_MSG;
		return -1;
	} else if (status_ == AWAIT_MSG) {
		if (DP_FAILED(dp_recv_from_worker(&reply, call_type_)))  // TODO can fail (this `return -1` is only a wait loop)
			return -1;
		reply_.set_inuse(!!reply.vni_in_use.in_use);
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
	struct dpgrpc_request request = {
		.type = call_type_,
	};
	struct dpgrpc_reply reply;

	if (status_ == REQUEST) {
		new ResetVniCall(service_, cq_);
		switch (request_.type()) {
		case VniType::VNI_IPV4:
			request.vni_in_use.type = DP_VNI_IPV4;
			break;
		case VniType::VNI_IPV6:
			request.vni_in_use.type = DP_VNI_IPV6;
			break;
		case VniType::VNI_BOTH:
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

		reply_.set_allocated_status(CreateErrStatus(&reply));
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

int CheckInitializedCall::Proceed()
{
	if (status_ == REQUEST) {
		new CheckInitializedCall(service_, cq_);
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

int InitializeCall::Proceed()
{
	struct dpgrpc_request request = {
		.type = call_type_,
	};
	struct dpgrpc_reply reply;

	if (status_ == REQUEST) {
		new InitializeCall(service_, cq_);
		dp_send_to_worker(&request);  // TODO can fail
		status_ = AWAIT_MSG;
		DPGRPC_LOG_INFO("Initializing");
		return -1;
	} else if (status_ == AWAIT_MSG) {
		GRPCService* grpc_service = dynamic_cast<GRPCService*>(service_);
		grpc_service->SetInitStatus(true);
		if (DP_FAILED(dp_recv_from_worker(&reply, call_type_)))  // TODO can fail (this `return -1` is only a wait loop)
			return -1;
		reply_.set_allocated_status(CreateErrStatus(&reply));
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
	struct dpgrpc_request request = {
		.type = call_type_,
	};
	struct dpgrpc_reply reply;
	uint16_t i, size;
	char buf_str[INET6_ADDRSTRLEN];
	int ret_val;

	if (status_ == REQUEST) {
		new CreateLBCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		DPGRPC_LOG_INFO("Creating loadbalancer",
						DP_LOG_LBID(request_.loadbalancer_id().c_str()),
						DP_LOG_VNI(request_.vni()),
						DP_LOG_IPV4STR(request_.loadbalanced_ip().address().c_str()));
		snprintf(request.add_lb.lb_id, sizeof(request.add_lb.lb_id), "%s",
				 request_.loadbalancer_id().c_str());
		request.add_lb.vni = request_.vni();
		if (request_.loadbalanced_ip().ipver() == IPVersion::IPV4) {
			request.add_lb.ip_type = RTE_ETHER_TYPE_IPV4;
			ret_val = inet_aton(request_.loadbalanced_ip().address().c_str(),
					  (in_addr*)&request.add_lb.addr);
			if (ret_val == 0)
				DPGRPC_LOG_WARNING("Invalid loadbalancer VIP",
								   DP_LOG_IPV4STR(request_.loadbalanced_ip().address().c_str()));
			size = (request_.loadbalanced_ports_size() >= DP_LB_MAX_PORTS) ? DP_LB_MAX_PORTS : request_.loadbalanced_ports_size();
			for (i = 0; i < size; i++) {
				DPGRPC_LOG_INFO("Adding loadbalancer port",
								DP_LOG_LBID(request_.loadbalancer_id().c_str()),
								DP_LOG_PORT(request_.loadbalanced_ports(i).port()),
								DP_LOG_PROTO(request_.loadbalanced_ports(i).protocol()));
				request.add_lb.lbports[i].port = request_.loadbalanced_ports(i).port();
				if (request_.loadbalanced_ports(i).protocol() == TCP)
					request.add_lb.lbports[i].protocol = DP_IP_PROTO_TCP;
				if (request_.loadbalanced_ports(i).protocol() == UDP)
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
		inet_ntop(AF_INET6, reply.ul_addr.addr6, buf_str, INET6_ADDRSTRLEN);
		reply_.set_underlay_route(buf_str);
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
	struct dpgrpc_request request = {
		.type = call_type_,
	};
	struct dpgrpc_reply reply;

	if (status_ == REQUEST) {
		new DelLBCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		DPGRPC_LOG_INFO("Removing loadbalancer",
						DP_LOG_LBID(request_.loadbalancer_id().c_str()));
		snprintf(request.del_lb.lb_id, sizeof(request.del_lb.lb_id), "%s",
				 request_.loadbalancer_id().c_str());
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
	struct dpgrpc_request request = {
		.type = call_type_,
	};
	struct dpgrpc_reply reply;
	struct in_addr addr;
	LBPort *lb_port;
	LBIP *lb_ip;
	int i;

	if (status_ == REQUEST) {
		new GetLBCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		DPGRPC_LOG_DEBUG("Getting loadbalancer info",
						DP_LOG_LBID(request_.loadbalancer_id().c_str()));
		snprintf(request.get_lb.lb_id, sizeof(request.get_lb.lb_id), "%s",
				 request_.loadbalancer_id().c_str());
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
		reply_.set_vni(reply.lb.vni);
		lb_ip = new LBIP();
		addr.s_addr = reply.lb.addr;
		lb_ip->set_address(inet_ntoa(addr));
		if (reply.lb.ip_type == RTE_ETHER_TYPE_IPV4)
			lb_ip->set_ipver(IPVersion::IPV4);
		else
			lb_ip->set_ipver(IPVersion::IPV6);
		reply_.set_allocated_loadbalanced_ip(lb_ip);
		for (i = 0; i < DP_LB_MAX_PORTS; i++) {
			if (reply.lb.lbports[i].port == 0)
				continue;
			lb_port = reply_.add_loadbalanced_ports();
			lb_port->set_port(reply.lb.lbports[i].port);
			if (reply.lb.lbports[i].protocol == DP_IP_PROTO_TCP)
				lb_port->set_protocol(TCP);
			if (reply.lb.lbports[i].protocol == DP_IP_PROTO_UDP)
				lb_port->set_protocol(UDP);
		}
		inet_ntop(AF_INET6, reply.lb.ul_addr6, buf_str, INET6_ADDRSTRLEN);
		reply_.set_underlay_route(buf_str);
		reply_.set_allocated_status(CreateErrStatus(&reply));
		responder_.Finish(reply_, ret, this);
	} else {
		GPR_ASSERT(status_ == FINISH);
		delete this;
	}
	return 0;
}

int CreateLBVIPCall::Proceed()
{
	struct dpgrpc_request request = {
		.type = call_type_,
	};
	struct dpgrpc_reply reply;
	int ret_val;

	if (status_ == REQUEST) {
		new CreateLBVIPCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		DPGRPC_LOG_INFO("Adding loadbalancer target",
						DP_LOG_LBID(request_.loadbalancer_id().c_str()),
						DP_LOG_IPV6STR(request_.target_ip().address().c_str()));
		snprintf(request.add_lbtrgt.lb_id, sizeof(request.add_lbtrgt.lb_id), "%s",
				 request_.loadbalancer_id().c_str());
		if (request_.target_ip().ipver() == IPVersion::IPV6) {
			request.add_lbtrgt.ip_type = RTE_ETHER_TYPE_IPV6;
			ret_val = inet_pton(AF_INET6, request_.target_ip().address().c_str(),
					  request.add_lbtrgt.addr6);
			if (ret_val <= 0)
				DPGRPC_LOG_WARNING("Invalid loadbalancer target IP",
								   DP_LOG_IPV6STR(request_.target_ip().address().c_str()));
		} else {
			request.add_lbtrgt.ip_type = RTE_ETHER_TYPE_IPV4;
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
		reply_.set_allocated_status(CreateErrStatus(&reply));
		responder_.Finish(reply_, ret, this);
	} else {
		GPR_ASSERT(status_ == FINISH);
		delete this;
	}
	return 0;
}

int DelLBVIPCall::Proceed()
{
	struct dpgrpc_request request = {
		.type = call_type_,
	};
	struct dpgrpc_reply reply;
	int ret_val;

	if (status_ == REQUEST) {
		new DelLBVIPCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		DPGRPC_LOG_INFO("Removing loadbalancer target",
						DP_LOG_LBID(request_.loadbalancer_id().c_str()),
						DP_LOG_IPV6STR(request_.target_ip().address().c_str()));
		snprintf(request.del_lbtrgt.lb_id, sizeof(request.del_lbtrgt.lb_id), "%s",
				 request_.loadbalancer_id().c_str());
		if (request_.target_ip().ipver() == IPVersion::IPV6) {
			request.del_lbtrgt.ip_type = RTE_ETHER_TYPE_IPV6;
			ret_val = inet_pton(AF_INET6, request_.target_ip().address().c_str(),
					  request.del_lbtrgt.addr6);
			if (ret_val <= 0)
				DPGRPC_LOG_WARNING("Invalid loadbalancer target IP",
								   DP_LOG_IPV6STR(request_.target_ip().address().c_str()));
		} else {
			request.del_lbtrgt.ip_type = RTE_ETHER_TYPE_IPV4;
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
		reply_.set_allocated_status(CreateErrStatus(&reply));
		responder_.Finish(reply_, ret, this);
	} else {
		GPR_ASSERT(status_ == FINISH);
		delete this;
	}
	return 0;
}

void GetLBVIPBackendsCall::ListCallback(struct dpgrpc_reply *reply, void *context)
{
	struct dpgrpc_lb_target *lb_target = (struct dpgrpc_lb_target *)reply;
	ListLoadBalancerTargetsResponse *reply_ = (ListLoadBalancerTargetsResponse *)context;
	LBIP *target_ip;
	char buf_str[INET6_ADDRSTRLEN];

	if (reply->err_code) {
		reply_->set_allocated_status(CreateErrStatus(reply));
		return;
	}

	for (uint i = 0; i < reply->msg_count; ++i) {
		lb_target = DPGRPC_GET_MESSAGE(reply, i, struct dpgrpc_lb_target);
		target_ip = reply_->add_target_ips();
		inet_ntop(AF_INET6, lb_target->addr6, buf_str, INET6_ADDRSTRLEN);
		target_ip->set_address(buf_str);
		target_ip->set_ipver(IPVersion::IPV6);
	}
}

int GetLBVIPBackendsCall::Proceed()
{
	struct dpgrpc_request request = {
		.type = call_type_,
	};

	if (status_ == REQUEST) {
		new GetLBVIPBackendsCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		DPGRPC_LOG_DEBUG("Listing loadbalancer targets",
						DP_LOG_LBID(request_.loadbalancer_id().c_str()));
		snprintf(request.list_lbtrgt.lb_id, sizeof(request.list_lbtrgt.lb_id), "%s",
				 request_.loadbalancer_id().c_str());
		dp_send_to_worker(&request);  // TODO can fail
		status_ = AWAIT_MSG;
		return -1;
	} else if (status_ == INITCHECK) {
		responder_.Finish(reply_, ret, this);
		status_ = FINISH;
	} else if (status_ == AWAIT_MSG) {
		// TODO can fail hard (this `return -1` is only a wait loop)
		if (DP_FAILED(dp_recv_array_from_worker(ListCallback, &reply_, call_type_)))
			return -1;
		status_ = FINISH;
		responder_.Finish(reply_, ret, this);
	} else {
		GPR_ASSERT(status_ == FINISH);
		delete this;
	}
	return 0;
}

int CreatePfxCall::Proceed()
{
	struct dpgrpc_request request = {
		.type = call_type_,
	};
	struct dpgrpc_reply reply;
	char buf_str[INET6_ADDRSTRLEN];
	int ret_val;

	if (status_ == REQUEST) {
		new CreatePfxCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		DPGRPC_LOG_INFO("Adding alias prefix",
						DP_LOG_IFACE(request_.interface_id().c_str()),
						DP_LOG_PREFIX(request_.prefix().address().c_str()),
						DP_LOG_PREFLEN(request_.prefix().length()));
		snprintf(request.add_pfx.iface_id, sizeof(request.add_pfx.iface_id),
				 "%s", request_.interface_id().c_str());
		if (request_.prefix().ipver() == IPVersion::IPV4) {
			request.add_pfx.ip_type = RTE_ETHER_TYPE_IPV4;
			ret_val = inet_aton(request_.prefix().address().c_str(),
					  (in_addr*)&request.add_pfx.addr);
			if (ret_val == 0)
				DPGRPC_LOG_WARNING("Invalid alias prefix IP",
								   DP_LOG_IPV4STR(request_.prefix().address().c_str()));
		}
		request.add_pfx.length = request_.prefix().length();
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
		inet_ntop(AF_INET6, reply.ul_addr.addr6, buf_str, INET6_ADDRSTRLEN);
		reply_.set_underlay_route(buf_str);
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
	struct dpgrpc_request request = {
		.type = call_type_,
	};
	struct dpgrpc_reply reply;
	int ret_val;

	if (status_ == REQUEST) {
		new DelPfxCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		DPGRPC_LOG_INFO("Removing alias prefix",
						DP_LOG_IFACE(request_.interface_id().c_str()),
						DP_LOG_PREFIX(request_.prefix().address().c_str()),
						DP_LOG_PREFLEN(request_.prefix().length()));
		snprintf(request.del_pfx.iface_id, sizeof(request.del_pfx.iface_id),
				 "%s", request_.interface_id().c_str());
		if (request_.prefix().ipver() == IPVersion::IPV4) {
			request.del_pfx.ip_type = RTE_ETHER_TYPE_IPV4;
			ret_val = inet_aton(request_.prefix().address().c_str(),
					  (in_addr*)&request.del_pfx.addr);
			if (ret_val == 0)
				DPGRPC_LOG_WARNING("Invalid alias prefix IP",
								   DP_LOG_PREFIX(request_.prefix().address().c_str()));
		}
		request.del_pfx.length = request_.prefix().length();
		dp_send_to_worker(&request);  // TODO can fail
		status_ = AWAIT_MSG;
		return -1;
	} else if (status_ == INITCHECK) {
		responder_.Finish(reply_, ret, this);
		status_ = FINISH;
	} else if (status_ == AWAIT_MSG) {
		if (DP_FAILED(dp_recv_from_worker(&reply, call_type_)))  // TODO can fail (this `return -1` is only a wait loop)
			return -1;
		reply_.set_allocated_status(CreateErrStatus(&reply));
		status_ = FINISH;
		responder_.Finish(reply_, ret, this);
	} else {
		GPR_ASSERT(status_ == FINISH);
		delete this;
	}
	return 0;
}

void ListPfxCall::ListCallback(struct dpgrpc_reply *reply, void *context)
{
	struct dpgrpc_route *rp_route;
	ListInterfacePrefixesResponse *reply_ = (ListInterfacePrefixesResponse *)context;
	Prefix *pfx;
	struct in_addr addr;
	char buf_str[INET6_ADDRSTRLEN];

	if (reply->err_code) {
		reply_->set_allocated_status(CreateErrStatus(reply));
		return;
	}

	for (uint i = 0; i < reply->msg_count; ++i) {
		rp_route = DPGRPC_GET_MESSAGE(reply, i, struct dpgrpc_route);
		pfx = reply_->add_prefixes();
		if (rp_route->pfx_ip_type == RTE_ETHER_TYPE_IPV4) {
			addr.s_addr = htonl(rp_route->pfx_addr);
			pfx->set_address(inet_ntoa(addr));
			pfx->set_ipver(IPVersion::IPV4);
			pfx->set_length(rp_route->pfx_length);
			inet_ntop(AF_INET6, rp_route->trgt_addr6, buf_str, INET6_ADDRSTRLEN);
			pfx->set_underlay_route(buf_str);
		}
		// TODO else? (should already be covered by the worker)
	}
}

int ListPfxCall::Proceed()
{
	struct dpgrpc_request request = {
		.type = call_type_,
	};

	if (status_ == REQUEST) {
		new ListPfxCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		DPGRPC_LOG_DEBUG("Listing alias prefixes",
						DP_LOG_IFACE(request_.interface_id().c_str()));
		snprintf(request.list_pfx.iface_id, sizeof(request.list_pfx.iface_id),
				 "%s", request_.interface_id().c_str());
		dp_send_to_worker(&request);  // TODO can fail
		status_ = AWAIT_MSG;
		return -1;
	} else if (status_ == INITCHECK) {
		responder_.Finish(reply_, ret, this);
		status_ = FINISH;
	} else if (status_ == AWAIT_MSG) {
		// TODO can fail hard (this `return -1` is only a wait loop)
		if (DP_FAILED(dp_recv_array_from_worker(ListCallback, &reply_, call_type_)))
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
	struct dpgrpc_request request = {
		.type = call_type_,
	};
	struct dpgrpc_reply reply;
	int ret_val;

	if (status_ == REQUEST) {
		new CreateLBTargetPfxCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		DPGRPC_LOG_INFO("Adding loadbalancer target prefix",
						DP_LOG_IFACE(request_.interface_id().c_str()),
						DP_LOG_PREFIX(request_.prefix().address().c_str()),
						DP_LOG_PREFLEN(request_.prefix().length()));
		snprintf(request.add_lbpfx.iface_id, sizeof(request.add_lbpfx.iface_id),
				 "%s", request_.interface_id().c_str());
		if (request_.prefix().ipver() == IPVersion::IPV4) {
			request.add_lbpfx.ip_type = RTE_ETHER_TYPE_IPV4;
			ret_val = inet_aton(request_.prefix().address().c_str(),
					  (in_addr*)&request.add_lbpfx.addr);
			if (ret_val == 0)
				DPGRPC_LOG_WARNING("Invalid target prefix IP",
								   DP_LOG_PREFIX(request_.prefix().address().c_str()));
		}
		request.add_lbpfx.length = request_.prefix().length();
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
		inet_ntop(AF_INET6, reply.route.trgt_addr6, buf_str, INET6_ADDRSTRLEN);
		reply_.set_underlay_route(buf_str);
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
	struct dpgrpc_request request = {
		.type = call_type_,
	};
	struct dpgrpc_reply reply;
	int ret_val;

	if (status_ == REQUEST) {
		new DelLBTargetPfxCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		DPGRPC_LOG_INFO("Removing loadbalancer target prefix",
						DP_LOG_IFACE(request_.interface_id().c_str()),
						DP_LOG_PREFIX(request_.prefix().address().c_str()),
						DP_LOG_PREFLEN(request_.prefix().length()));
		snprintf(request.del_lbpfx.iface_id, sizeof(request.del_lbpfx.iface_id),
				 "%s", request_.interface_id().c_str());
		if (request_.prefix().ipver() == IPVersion::IPV4) {
			request.del_lbpfx.ip_type = RTE_ETHER_TYPE_IPV4;
			ret_val = inet_aton(request_.prefix().address().c_str(),
					  (in_addr*)&request.del_lbpfx.addr);
			if (ret_val == 0)
				DPGRPC_LOG_WARNING("Invalid target prefix IP",
								   DP_LOG_PREFIX(request_.prefix().address().c_str()));
		}
		request.del_lbpfx.length = request_.prefix().length();
		dp_send_to_worker(&request);  // TODO can fail
		status_ = AWAIT_MSG;
		return -1;
	} else if (status_ == INITCHECK) {
		responder_.Finish(reply_, ret, this);
		status_ = FINISH;
	} else if (status_ == AWAIT_MSG) {
		if (DP_FAILED(dp_recv_from_worker(&reply, call_type_)))  // TODO can fail (this `return -1` is only a wait loop)
			return -1;
		reply_.set_allocated_status(CreateErrStatus(&reply));
		status_ = FINISH;
		responder_.Finish(reply_, ret, this);
	} else {
		GPR_ASSERT(status_ == FINISH);
		delete this;
	}
	return 0;
}

void ListLBTargetPfxCall::ListCallback(struct dpgrpc_reply *reply, void *context)
{
	struct dpgrpc_route *rp_route;
	ListInterfaceLoadBalancerPrefixesResponse *reply_ = (ListInterfaceLoadBalancerPrefixesResponse *)context;
	Prefix *pfx;
	struct in_addr addr;
	char buf_str[INET6_ADDRSTRLEN];

	if (reply->err_code) {
		reply_->set_allocated_status(CreateErrStatus(reply));
		return;
	}

	for (uint i = 0; i < reply->msg_count; ++i) {
		rp_route = DPGRPC_GET_MESSAGE(reply, i, struct dpgrpc_route);
		pfx = reply_->add_prefixes();
		if (rp_route->pfx_ip_type == RTE_ETHER_TYPE_IPV4) {
			addr.s_addr = htonl(rp_route->pfx_addr);
			pfx->set_address(inet_ntoa(addr));
			pfx->set_ipver(IPVersion::IPV4);
			pfx->set_length(rp_route->pfx_length);
			inet_ntop(AF_INET6, rp_route->trgt_addr6, buf_str, INET6_ADDRSTRLEN);
			pfx->set_underlay_route(buf_str);
		}
		// TODO else? (should already be covered by the worker)
	}
}

int ListLBTargetPfxCall::Proceed()
{
	struct dpgrpc_request request = {
		.type = call_type_,
	};

	if (status_ == REQUEST) {
		new ListLBTargetPfxCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		DPGRPC_LOG_DEBUG("Listing loadbalancer target prefixes",
						DP_LOG_IFACE(request_.interface_id().c_str()));
		snprintf(request.list_lbpfx.iface_id, sizeof(request.list_lbpfx.iface_id),
				 "%s", request_.interface_id().c_str());
		dp_send_to_worker(&request);  // TODO can fail
		status_ = AWAIT_MSG;
		return -1;
	} else if (status_ == INITCHECK) {
		responder_.Finish(reply_, ret, this);
		status_ = FINISH;
	} else if (status_ == AWAIT_MSG) {
		// TODO can fail hard (this `return -1` is only a wait loop)
		if (DP_FAILED(dp_recv_array_from_worker(ListCallback, &reply_, call_type_)))
			return -1;
		status_ = FINISH;
		responder_.Finish(reply_, ret, this);
	} else {
		GPR_ASSERT(status_ == FINISH);
		delete this;
	}
	return 0;
}

int CreateVIPCall::Proceed()
{
	struct dpgrpc_request request = {
		.type = call_type_,
	};
	struct dpgrpc_reply reply;
	char buf_str[INET6_ADDRSTRLEN];
	int ret_val;

	if (status_ == REQUEST) {
		new CreateVIPCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		DPGRPC_LOG_INFO("Setting virtual IP",
						DP_LOG_IFACE(request_.interface_id().c_str()),
						DP_LOG_IPV4STR(request_.vip().address().c_str()));
		snprintf(request.add_vip.iface_id, sizeof(request.add_vip.iface_id),
				 "%s", request_.interface_id().c_str());
		if (request_.vip().ipver() == IPVersion::IPV4) {
			request.add_vip.ip_type = RTE_ETHER_TYPE_IPV4;
			ret_val = inet_aton(request_.vip().address().c_str(),
					  (in_addr*)&request.add_vip.addr);
			if (ret_val == 0)
				DPGRPC_LOG_WARNING("Invalid virtual IP",
								   DP_LOG_IPV4STR(request_.vip().address().c_str()));
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
		inet_ntop(AF_INET6, reply.ul_addr.addr6, buf_str, INET6_ADDRSTRLEN);
		reply_.set_underlay_route(buf_str);
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
	struct dpgrpc_request request = {
		.type = call_type_,
	};
	struct dpgrpc_reply reply;

	if (status_ == REQUEST) {
		new DelVIPCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		DPGRPC_LOG_INFO("Removing virtual IP",
						DP_LOG_IFACE(request_.interface_id().c_str()));
		snprintf(request.del_vip.iface_id, sizeof(request.del_vip.iface_id),
				 "%s", request_.interface_id().c_str());
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
	struct dpgrpc_request request = {
		.type = call_type_,
	};
	struct dpgrpc_reply reply;
	struct in_addr addr;
	InterfaceVIPIP *vip;

	if (status_ == REQUEST) {
		new GetVIPCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		DPGRPC_LOG_DEBUG("Getting virtual IP",
						DP_LOG_IFACE(request_.interface_id().c_str()));
		snprintf(request.get_vip.iface_id, sizeof(request.get_vip.iface_id),
				 "%s", request_.interface_id().c_str());
		dp_send_to_worker(&request);  // TODO can fail
		status_ = AWAIT_MSG;
		return -1;
	} else if (status_ == INITCHECK) {
		responder_.Finish(reply_, ret, this);
		status_ = FINISH;
	} else if (status_ == AWAIT_MSG) {
		if (DP_FAILED(dp_recv_from_worker(&reply, call_type_)))  // TODO can fail (this `return -1` is only a wait loop)
			return -1;
		vip = new InterfaceVIPIP();
		vip->set_ipver(IPVersion::IPV4);
		addr.s_addr = reply.vip.addr;
		vip->set_address(inet_ntoa(addr));
		inet_ntop(AF_INET6, reply.vip.ul_addr6, buf_str, INET6_ADDRSTRLEN);
		vip->set_underlay_route(buf_str);
		reply_.set_allocated_vip(vip);
		status_ = FINISH;
		reply_.set_allocated_status(CreateErrStatus(&reply));
		responder_.Finish(reply_, ret, this);
	} else {
		GPR_ASSERT(status_ == FINISH);
		delete this;
	}
	return 0;
}

int CreateInterfaceCall::Proceed()
{
	struct dpgrpc_request request = {
		.type = call_type_,
	};
	struct dpgrpc_reply reply;
	VirtualFunction *vf;
	char buf_str[INET6_ADDRSTRLEN];
	int ret_val;

	if (status_ == REQUEST) {
		new CreateInterfaceCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		DPGRPC_LOG_INFO("Adding interface",
						DP_LOG_IFACE(request_.interface_id().c_str()),
						DP_LOG_VNI(request_.vni()),
						DP_LOG_IPV4STR(request_.ipv4_config().primary_address().c_str()),
						DP_LOG_IPV6STR(request_.ipv6_config().primary_address().c_str()),
						DP_LOG_PCI(request_.device_name().c_str()));
		request.add_iface.vni = request_.vni();
		ret_val = inet_aton(request_.ipv4_config().primary_address().c_str(),
				(in_addr*)&request.add_iface.ip4_addr);
		if (ret_val == 0)
			DPGRPC_LOG_WARNING("AddInterface: wrong primary IP",
							   DP_LOG_IPV4STR(request_.ipv4_config().primary_address().c_str()));
		if (!request_.pxe_config().next_server().empty()) {
			DPGRPC_LOG_INFO("Setting PXE",
							DP_LOG_IFACE(request_.interface_id().c_str()),
							DP_LOG_PXE_SRV(request_.pxe_config().next_server().c_str()),
							DP_LOG_PXE_PATH(request_.pxe_config().boot_filename().c_str()));
			ret_val = inet_aton(request_.pxe_config().next_server().c_str(),
					(in_addr*)&request.add_iface.ip4_pxe_addr);
			if (ret_val == 0)
				DPGRPC_LOG_WARNING("AddInterface: wrong PXE next server IP",
								   DP_LOG_IPV4STR(request_.pxe_config().next_server().c_str()));
		}
		snprintf(request.add_iface.pxe_str, sizeof(request.add_iface.pxe_str), "%s",
				 request_.pxe_config().boot_filename().c_str());
		snprintf(request.add_iface.pci_name, sizeof(request.add_iface.pci_name), "%s",
				 request_.device_name().c_str());
		ret_val = inet_pton(AF_INET6, request_.ipv6_config().primary_address().c_str(),
								request.add_iface.ip6_addr);
		if (ret_val <= 0)
			DPGRPC_LOG_WARNING("AddInterface: wrong IPv6 primary IP",
							   DP_LOG_IPV6STR(request_.ipv6_config().primary_address().c_str()));
		snprintf(request.add_iface.iface_id, sizeof(request.add_iface.iface_id), "%s",
				 request_.interface_id().c_str());
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
		reply_.set_underlay_route(buf_str);
		reply_.set_allocated_status(CreateErrStatus(&reply));
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
	struct dpgrpc_request request = {
		.type = call_type_,
	};
	struct dpgrpc_reply reply;

	if (status_ == REQUEST) {
		new DelInterfaceCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		DPGRPC_LOG_INFO("Removing interface",
						DP_LOG_IFACE(request_.interface_id().c_str()));
		snprintf(request.del_iface.iface_id, sizeof(request.del_iface.iface_id),
				 "%s", request_.interface_id().c_str());
		dp_send_to_worker(&request);  // TODO can fail
		status_ = AWAIT_MSG;
		return -1;
	} else if (status_ == INITCHECK) {
		responder_.Finish(reply_, ret, this);
		status_ = FINISH;
	} else if (status_ == AWAIT_MSG) {
		if (DP_FAILED(dp_recv_from_worker(&reply, call_type_)))  // TODO can fail (this `return -1` is only a wait loop)
			return -1;
		reply_.set_allocated_status(CreateErrStatus(&reply));
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
	struct dpgrpc_request request = {
		.type = call_type_,
	};
	struct dpgrpc_reply reply;
	struct dpgrpc_iface *iface;
	Interface *machine;
	struct in_addr addr;
	char buf_str[INET6_ADDRSTRLEN];

	if (status_ == REQUEST) {
		new GetInterfaceCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		DPGRPC_LOG_DEBUG("Getting interface info",
						DP_LOG_IFACE(request_.interface_id().c_str()));
		snprintf(request.get_iface.iface_id, sizeof(request.get_iface.iface_id),
				 "%s", request_.interface_id().c_str());
		dp_send_to_worker(&request);  // TODO can fail
		status_ = AWAIT_MSG;
		return -1;
	} else if (status_ == INITCHECK) {
		responder_.Finish(reply_, ret, this);
		status_ = FINISH;
	} else if (status_ == AWAIT_MSG) {
		if (DP_FAILED(dp_recv_from_worker(&reply, call_type_)))  // TODO can fail (this `return -1` is only a wait loop)
			return -1;

		iface = &reply.iface;
		addr.s_addr = htonl(iface->ip4_addr);
		machine = new Interface();
		machine->set_primary_ipv4(inet_ntoa(addr));
		inet_ntop(AF_INET6, iface->ip6_addr, buf_str, INET6_ADDRSTRLEN);
		machine->set_primary_ipv6(buf_str);
		machine->set_id((char *)iface->iface_id);
		machine->set_vni(iface->vni);
		machine->set_pci_name(iface->pci_name);

		inet_ntop(AF_INET6, reply.iface.ul_addr6, buf_str, INET6_ADDRSTRLEN);
		machine->set_underlay_route(buf_str);
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

int CreateRouteCall::Proceed()
{
	struct dpgrpc_request request = {
		.type = call_type_,
	};
	struct dpgrpc_reply reply;
	int ret_val;

	if (status_ == REQUEST) {
		new CreateRouteCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		DPGRPC_LOG_INFO("Adding route",
						DP_LOG_VNI(request_.vni()),
						DP_LOG_PREFIX(request_.route().prefix().address().c_str()),
						DP_LOG_PREFLEN(request_.route().prefix().length()),
						DP_LOG_TVNI(request_.route().nexthop_vni()),
						DP_LOG_IPV6STR(request_.route().nexthop_address().c_str()));
		request.add_route.vni = request_.vni();
		request.add_route.trgt_ip_type = RTE_ETHER_TYPE_IPV6;
		request.add_route.trgt_vni = request_.route().nexthop_vni();
		ret_val = inet_pton(AF_INET6, request_.route().nexthop_address().c_str(), request.add_route.trgt_addr6);
		if (ret_val <= 0)
			DPGRPC_LOG_WARNING("Invalid nexthop IP", DP_LOG_IPV6STR(request_.route().nexthop_address().c_str()));
		request.add_route.pfx_length = request_.route().prefix().length();
		if (request_.route().prefix().ipver() == IPVersion::IPV4) {
			request.add_route.pfx_ip_type = RTE_ETHER_TYPE_IPV4;
			ret_val = inet_aton(request_.route().prefix().address().c_str(),
					(in_addr*)&request.add_route.pfx_addr);
			if (ret_val == 0)
				DPGRPC_LOG_WARNING("Invalid prefix IP", DP_LOG_PREFIX(request_.route().prefix().address().c_str()));
		} else {
			request.add_route.pfx_ip_type = RTE_ETHER_TYPE_IPV6;
			ret_val = inet_pton(AF_INET6, request_.route().prefix().address().c_str(), request.add_route.pfx_addr6);
			if (ret_val <= 0)
				DPGRPC_LOG_WARNING("Invalid prefix IP", DP_LOG_PREFIX(request_.route().prefix().address().c_str()));
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
		reply_.set_allocated_status(CreateErrStatus(&reply));
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
	struct dpgrpc_request request = {
		.type = call_type_,
	};
	struct dpgrpc_reply reply;
	int ret_val;

	if (status_ == REQUEST) {
		new DelRouteCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		DPGRPC_LOG_INFO("Removing route",
						DP_LOG_VNI(request_.vni()),
						DP_LOG_PREFIX(request_.route().prefix().address().c_str()),
						DP_LOG_PREFLEN(request_.route().prefix().length()),
						DP_LOG_TVNI(request_.route().nexthop_vni()), // TODO re-check for target vni everywhere
						DP_LOG_IPV6STR(request_.route().nexthop_address().c_str()));
		request.del_route.vni = request_.vni();
		request.del_route.trgt_ip_type = RTE_ETHER_TYPE_IPV6;
		request.del_route.trgt_vni = request_.route().nexthop_vni();
		if (!request_.route().nexthop_address().empty()) {
			ret_val = inet_pton(AF_INET6, request_.route().nexthop_address().c_str(),
					request.del_route.trgt_addr6);
			if (ret_val <= 0)
				DPGRPC_LOG_WARNING("Invalid nexthop IP",
								   DP_LOG_IPV6STR(request_.route().nexthop_address().c_str()));
		}
		request.del_route.pfx_length = request_.route().prefix().length();
		if (request_.route().prefix().ipver() == IPVersion::IPV4) {
			request.del_route.pfx_ip_type = RTE_ETHER_TYPE_IPV4;
			ret_val = inet_aton(request_.route().prefix().address().c_str(),
					(in_addr*)&request.del_route.pfx_addr);
			if (ret_val == 0)
				DPGRPC_LOG_WARNING("Invalid prefix IP",
								   DP_LOG_PREFIX(request_.route().prefix().address().c_str()));
		} else {
			request.del_route.pfx_ip_type = RTE_ETHER_TYPE_IPV6;
			ret_val = inet_pton(AF_INET6, request_.route().prefix().address().c_str(),
					request.del_route.pfx_addr6);
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
		reply_.set_allocated_status(CreateErrStatus(&reply));
		status_ = FINISH;
		responder_.Finish(reply_, ret, this);
	} else {
		GPR_ASSERT(status_ == FINISH);
		delete this;
	}
	return 0;
}

void ListRoutesCall::ListCallback(struct dpgrpc_reply *reply, void *context)
{
	struct dpgrpc_route *rp_route;
	ListRoutesResponse *reply_ = (ListRoutesResponse *)context;
	Route *route;
	struct in_addr addr;
	Prefix *pfx;
	char buf[INET6_ADDRSTRLEN];

	if (reply->err_code) {
		reply_->set_allocated_status(CreateErrStatus(reply));
		return;
	}

	for (uint i = 0; i < reply->msg_count; ++i) {
		rp_route = DPGRPC_GET_MESSAGE(reply, i, struct dpgrpc_route);

		route = reply_->add_routes();
		if (rp_route->trgt_ip_type == RTE_ETHER_TYPE_IPV6)
			route->set_ipver(IPVersion::IPV6);
		else
			route->set_ipver(IPVersion::IPV4);

		if (rp_route->pfx_ip_type == RTE_ETHER_TYPE_IPV4) {
			addr.s_addr = htonl(rp_route->pfx_addr);
			pfx = new Prefix();
			pfx->set_address(inet_ntoa(addr));
			pfx->set_ipver(IPVersion::IPV4);
			pfx->set_length(rp_route->pfx_length);
			route->set_allocated_prefix(pfx);
		}
		route->set_nexthop_vni(rp_route->trgt_vni);
		inet_ntop(AF_INET6, rp_route->trgt_addr6, buf, INET6_ADDRSTRLEN);
		route->set_nexthop_address(buf);
	}
}

int ListRoutesCall::Proceed()
{
	struct dpgrpc_request request = {
		.type = call_type_,
	};

	if (status_ == REQUEST) {
		new ListRoutesCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		DPGRPC_LOG_DEBUG("Listing routes",
						DP_LOG_VNI(request_.vni()));
		request.list_route.vni = request_.vni();
		request.list_route.type = DP_VNI_BOTH;
		dp_send_to_worker(&request);  // TODO can fail
		status_ = AWAIT_MSG;
		return -1;
	} else if (status_ == INITCHECK) {
		responder_.Finish(reply_, ret, this);
		status_ = FINISH;
	} else if (status_ == AWAIT_MSG) {
		// TODO can fail hard (this `return -1` is only a wait loop)
		if (DP_FAILED(dp_recv_array_from_worker(ListCallback, &reply_, call_type_)))
			return -1;
		status_ = FINISH;
		responder_.Finish(reply_, ret, this);
	} else {
		GPR_ASSERT(status_ == FINISH);
		delete this;
	}
	return 0;
}

int CreateNATVIPCall::Proceed()
{
	struct dpgrpc_request request = {
		.type = call_type_,
	};
	struct dpgrpc_reply reply;

	char buf_str[INET6_ADDRSTRLEN];
	int ret_val;

	if (status_ == REQUEST) {
		new CreateNATVIPCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		DPGRPC_LOG_INFO("Setting NAT IP",
						DP_LOG_IFACE(request_.interface_id().c_str()),
						DP_LOG_IPV4STR(request_.nat_ip().address().c_str()),
						DP_LOG_MINPORT(request_.min_port()),
						DP_LOG_MAXPORT(request_.max_port()));
		snprintf(request.add_nat.iface_id, sizeof(request.add_nat.iface_id),
				 "%s", request_.interface_id().c_str());
		if (request_.nat_ip().ipver() == IPVersion::IPV4) {
			request.add_nat.ip_type = RTE_ETHER_TYPE_IPV4;
			ret_val = inet_aton(request_.nat_ip().address().c_str(),
					  (in_addr*)&request.add_nat.addr);
			if (ret_val == 0)
				DPGRPC_LOG_WARNING("Invalid NAT IP",
								   DP_LOG_IPV4STR(request_.nat_ip().address().c_str()));
		}
		// maybe add a validity check here to ensure minport is not greater than 2^30
		request.add_nat.min_port = request_.min_port();
		request.add_nat.max_port = request_.max_port();
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
		inet_ntop(AF_INET6, reply.ul_addr.addr6, buf_str, INET6_ADDRSTRLEN);
		reply_.set_underlay_route(buf_str);
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
	struct dpgrpc_request request = {
		.type = call_type_,
	};
	struct dpgrpc_reply reply;
	struct in_addr addr;
	NATIP *nat_ip;
	char buf[INET6_ADDRSTRLEN];

	if (status_ == REQUEST) {
		new GetNATVIPCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		DPGRPC_LOG_DEBUG("Getting NAT IP",
						DP_LOG_IFACE(request_.interface_id().c_str()));
		snprintf(request.get_vip.iface_id, sizeof(request.get_vip.iface_id),
				 "%s", request_.interface_id().c_str());
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
		addr.s_addr = reply.nat.addr;
		nat_ip->set_address(inet_ntoa(addr));
		nat_ip->set_ipver(IPVersion::IPV4);
		reply_.set_allocated_nat_ip(nat_ip);
		reply_.set_max_port(reply.nat.max_port);
		reply_.set_min_port(reply.nat.min_port);
		inet_ntop(AF_INET6, reply.nat.ul_addr6, buf, INET6_ADDRSTRLEN);
		reply_.set_underlay_route(buf);
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
	struct dpgrpc_request request = {
		.type = call_type_,
	};
	struct dpgrpc_reply reply;

	if (status_ == REQUEST) {
		new DeleteNATVIPCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		DPGRPC_LOG_INFO("Removing NAT IP",
						DP_LOG_IFACE(request_.interface_id().c_str()));
		snprintf(request.del_nat.iface_id, sizeof(request.del_nat.iface_id),
				 "%s", request_.interface_id().c_str());
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
		reply_.set_allocated_status(CreateErrStatus(&reply));
		responder_.Finish(reply_, ret, this);
	} else {
		GPR_ASSERT(status_ == FINISH);
		delete this;
	}
	return 0;
}

int CreateNeighborNATCall::Proceed()
{
	struct dpgrpc_request request = {
		.type = call_type_,
	};
	struct dpgrpc_reply reply;
	int ret_val;

	if (status_ == REQUEST) {
		new CreateNeighborNATCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		DPGRPC_LOG_INFO("Adding neighboring NAT",
						DP_LOG_VNI(request_.vni()),
						DP_LOG_IPV4STR(request_.nat_ip().address().c_str()),
						DP_LOG_MINPORT(request_.min_port()),
						DP_LOG_MAXPORT(request_.max_port()),
						DP_LOG_IPV6STR(request_.underlay_route().c_str()));
		if (request_.nat_ip().ipver() == IPVersion::IPV4) {
			request.add_neighnat.ip_type = RTE_ETHER_TYPE_IPV4;
			ret_val = inet_aton(request_.nat_ip().address().c_str(),
					  (in_addr*)&request.add_neighnat.addr);
			if (ret_val == 0)
				DPGRPC_LOG_WARNING("Invalid NAT IP",
								   DP_LOG_IPV4STR(request_.nat_ip().address().c_str()));
		}
		// FIXME adding ipv6 will break this
		// maybe add a validity check here to ensure minport is not greater than 2^30
		request.add_neighnat.min_port = request_.min_port();
		request.add_neighnat.max_port = request_.max_port();
		request.add_neighnat.vni = request_.vni();
		ret_val = inet_pton(AF_INET6, request_.underlay_route().c_str(),
				request.add_neighnat.neigh_addr6);
		if (ret_val <= 0)
			DPGRPC_LOG_WARNING("Invalid underlay IP",
							   DP_LOG_IPV6STR(request_.underlay_route().c_str()));
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
		responder_.Finish(reply_, ret, this);
	} else {
		GPR_ASSERT(status_ == FINISH);
		delete this;
	}
	return 0;

}

int DeleteNeighborNATCall::Proceed()
{
	struct dpgrpc_request request = {
		.type = call_type_,
	};
	struct dpgrpc_reply reply;
	int ret_val;

	if (status_ == REQUEST) {
		new DeleteNeighborNATCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		DPGRPC_LOG_INFO("Removing neighboring NAT",
						DP_LOG_VNI(request_.vni()),
						DP_LOG_IPV4STR(request_.nat_ip().address().c_str()),
						DP_LOG_MINPORT(request_.min_port()),
						DP_LOG_MAXPORT(request_.max_port()));
		if (request_.nat_ip().ipver() == IPVersion::IPV4) {
			request.del_neighnat.ip_type = RTE_ETHER_TYPE_IPV4;
			ret_val = inet_aton(request_.nat_ip().address().c_str(),
					  (in_addr*)&request.del_neighnat.addr);
			if (ret_val == 0)
				DPGRPC_LOG_WARNING("Invalid NAT IP",
								   DP_LOG_IPV4STR(request_.nat_ip().address().c_str()));
		}
		// maybe add a validity check here to ensure minport is not greater than 2^30
		request.del_neighnat.min_port = request_.min_port();
		request.del_neighnat.max_port = request_.max_port();
		request.del_neighnat.vni = request_.vni();
		// neigh_addr6 field is implied by this unique NAT definition
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
		responder_.Finish(reply_, ret, this);
	} else {
		GPR_ASSERT(status_ == FINISH);
		delete this;
	}
	return 0;
}

void ListInterfacesCall::ListCallback(struct dpgrpc_reply *reply, void *context)
{
	struct dpgrpc_iface *iface;
	ListInterfacesResponse *reply_ = (ListInterfacesResponse *)context;
	Interface *machine;
	struct in_addr addr;
	char buf_str[INET6_ADDRSTRLEN];

	if (reply->err_code) {
		reply_->set_allocated_status(CreateErrStatus(reply));
		return;
	}

	for (uint i = 0; i < reply->msg_count; ++i) {
		iface = DPGRPC_GET_MESSAGE(reply, i, struct dpgrpc_iface);
		machine = reply_->add_interfaces();
		addr.s_addr = htonl(iface->ip4_addr);
		machine->set_primary_ipv4(inet_ntoa(addr));
		inet_ntop(AF_INET6, iface->ip6_addr, buf_str, INET6_ADDRSTRLEN);
		machine->set_primary_ipv6(buf_str);
		machine->set_id((char *)iface->iface_id);
		machine->set_vni(iface->vni);
		machine->set_pci_name(iface->pci_name);
		inet_ntop(AF_INET6, iface->ul_addr6, buf_str, INET6_ADDRSTRLEN);
		machine->set_underlay_route(buf_str);
	}
}

int ListInterfacesCall::Proceed()
{
	struct dpgrpc_request request = {
		.type = call_type_,
	};

	if (status_ == REQUEST) {
		new ListInterfacesCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		DPGRPC_LOG_DEBUG("Listing interfaces");
		dp_send_to_worker(&request);  // TODO can fail
		status_ = AWAIT_MSG;
		return -1;
	} else if (status_ == INITCHECK) {
		responder_.Finish(reply_, ret, this);
		status_ = FINISH;
	} else if (status_ == AWAIT_MSG) {
		// TODO can fail hard (this `return -1` is only a wait loop)
		if (DP_FAILED(dp_recv_array_from_worker(ListCallback, &reply_, call_type_)))
			return -1;
		status_ = FINISH;
		responder_.Finish(reply_, ret, this);
	} else {
		GPR_ASSERT(status_ == FINISH);
		delete this;
	}
	return 0;
}

void ListLocalNATsCall::ListCallback(struct dpgrpc_reply *reply, void *context)
{
	struct dpgrpc_nat *nat;
	ListLocalNATsResponse *reply_ = (ListLocalNATsResponse *)context;
	NATEntry *nat_entry;
	struct in_addr addr;

	if (reply->err_code) {
		reply_->set_allocated_status(CreateErrStatus(reply));
		return;
	}

	for (uint i = 0; i < reply->msg_count; ++i) {
		nat = DPGRPC_GET_MESSAGE(reply, i, struct dpgrpc_nat);
		nat_entry = reply_->add_nat_entries();
		addr.s_addr = htonl(nat->addr);
		nat_entry->set_ipver(IPVersion::IPV4);
		nat_entry->set_address(inet_ntoa(addr));
		nat_entry->set_min_port(nat->min_port);
		nat_entry->set_max_port(nat->max_port);
		nat_entry->set_vni(nat->vni);
	}
}

int ListLocalNATsCall::Proceed()
{
	struct dpgrpc_request request = {
		.type = call_type_,
	};
	int ret_val;

	if (status_ == REQUEST) {
		new ListLocalNATsCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		DPGRPC_LOG_INFO("Listing local NATs",
						DP_LOG_IPV4STR(request_.nat_ip().address().c_str()));

		if (request_.nat_ip().ipver() == IPVersion::IPV4) {
			request.list_neighnat.ip_type = RTE_ETHER_TYPE_IPV4;
			ret_val = inet_aton(request_.nat_ip().address().c_str(),
					  (in_addr*)&request.list_neighnat.addr);
			if (ret_val == 0)
				DPGRPC_LOG_WARNING("Invalid NAT IP",
								   DP_LOG_IPV4STR(request_.nat_ip().address().c_str()));
		}
		// TODO else?
		dp_send_to_worker(&request);  // TODO can fail
		status_ = AWAIT_MSG;
		return -1;
	} else if (status_ == INITCHECK) {
		responder_.Finish(reply_, ret, this);
		status_ = FINISH;
	} else if (status_ == AWAIT_MSG) {
		// TODO can fail hard (this `return -1` is only a wait loop)
		if (DP_FAILED(dp_recv_array_from_worker(ListCallback, &reply_, call_type_)))
			return -1;
		status_ = FINISH;
		responder_.Finish(reply_, ret, this);
	} else {
		GPR_ASSERT(status_ == FINISH);
		delete this;
	}
	return 0;
}

void ListNeighborNATsCall::ListCallback(struct dpgrpc_reply *reply, void *context)
{
	struct dpgrpc_nat *nat;
	ListNeighborNATsResponse *reply_ = (ListNeighborNATsResponse *)context;
	NATEntry *nat_entry;
	char buf[INET6_ADDRSTRLEN];

	if (reply->err_code) {
		reply_->set_allocated_status(CreateErrStatus(reply));
		return;
	}

	for (uint i = 0; i < reply->msg_count; ++i) {
		nat = DPGRPC_GET_MESSAGE(reply, i, struct dpgrpc_nat);
		nat_entry = reply_->add_nat_entries();
		inet_ntop(AF_INET6, nat->ul_addr6, buf, INET6_ADDRSTRLEN);
		nat_entry->set_underlay_route(buf);
		nat_entry->set_min_port(nat->min_port);
		nat_entry->set_max_port(nat->max_port);
		nat_entry->set_vni(nat->vni);
	}
}

int ListNeighborNATsCall::Proceed()
{
	struct dpgrpc_request request = {
		.type = call_type_,
	};
	int ret_val;

	if (status_ == REQUEST) {
		new ListNeighborNATsCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		DPGRPC_LOG_DEBUG("Getting NAT info",
						DP_LOG_IPV4STR(request_.nat_ip().address().c_str()));

		if (request_.nat_ip().ipver() == IPVersion::IPV4) {
			request.list_neighnat.ip_type = RTE_ETHER_TYPE_IPV4;
			ret_val = inet_aton(request_.nat_ip().address().c_str(),
					  (in_addr*)&request.list_neighnat.addr);
			if (ret_val == 0)
				DPGRPC_LOG_WARNING("Invalid NAT IP",
								   DP_LOG_IPV4STR(request_.nat_ip().address().c_str()));
		}
		// TODO else
		dp_send_to_worker(&request);  // TODO can fail
		status_ = AWAIT_MSG;
		return -1;
	} else if (status_ == INITCHECK) {
		responder_.Finish(reply_, ret, this);
		status_ = FINISH;
	} else if (status_ == AWAIT_MSG) {
		// TODO can fail hard (this `return -1` is only a wait loop)
		if (DP_FAILED(dp_recv_array_from_worker(ListCallback, &reply_, call_type_)))
			return -1;
		status_ = FINISH;
		responder_.Finish(reply_, ret, this);
	} else {
		GPR_ASSERT(status_ == FINISH);
		delete this;
	}
	return 0;
}

int CreateFirewallRuleCall::Proceed()
{
	struct dpgrpc_request request = {
		.type = call_type_,
	};
	struct dpgrpc_reply reply;
	const FirewallRule *grpc_rule;

	if (status_ == REQUEST) {
		new CreateFirewallRuleCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		grpc_rule = &request_.rule();
		DPGRPC_LOG_INFO("Adding firewall rule",
						DP_LOG_IFACE(request_.interface_id().c_str()),
						DP_LOG_FWRULE(grpc_rule->id().c_str()),
						DP_LOG_FWPRIO(grpc_rule->priority()),
						DP_LOG_FWDIR(grpc_rule->direction()),
						DP_LOG_FWACTION(grpc_rule->action()),
						DP_LOG_FWSRC(grpc_rule->source_prefix().address().c_str()),
						DP_LOG_FWSRCLEN(grpc_rule->source_prefix().length()),
						DP_LOG_FWDST(grpc_rule->destination_prefix().address().c_str()),
						DP_LOG_FWDSTLEN(grpc_rule->destination_prefix().length()));
		snprintf(request.add_fwrule.iface_id, sizeof(request.add_fwrule.iface_id),
				 "%s", request_.interface_id().c_str());
		ConvertGRPCFwallRuleToDPFWallRule(grpc_rule, &request.add_fwrule.rule);
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
		reply_.set_rule_id(&reply.fwrule.rule.rule_id, sizeof(reply.fwrule.rule.rule_id));
		responder_.Finish(reply_, ret, this);
	} else {
		GPR_ASSERT(status_ == FINISH);
		delete this;
	}
	return 0;
}

int DelFirewallRuleCall::Proceed()
{
	struct dpgrpc_request request = {
		.type = call_type_,
	};
	struct dpgrpc_reply reply;

	if (status_ == REQUEST) {
		new DelFirewallRuleCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		DPGRPC_LOG_INFO("Removing firewall rule",
						DP_LOG_IFACE(request_.interface_id().c_str()),
						DP_LOG_FWRULE(request_.rule_id().c_str()));
		snprintf(request.del_fwrule.iface_id, sizeof(request.del_fwrule.iface_id),
				 "%s", request_.interface_id().c_str());
		snprintf(request.del_fwrule.rule_id, sizeof(request.del_fwrule.rule_id),
				 "%s", request_.rule_id().c_str());
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
		responder_.Finish(reply_, ret, this);
	} else {
		GPR_ASSERT(status_ == FINISH);
		delete this;
	}
	return 0;
}

int GetFirewallRuleCall::Proceed()
{
	struct dpgrpc_request request = {
		.type = call_type_,
	};
	struct dpgrpc_reply reply;
	FirewallRule *rule;

	if (status_ == REQUEST) {
		new GetFirewallRuleCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		DPGRPC_LOG_DEBUG("Getting firewall rule info",
						DP_LOG_IFACE(request_.interface_id().c_str()),
						DP_LOG_FWRULE(request_.rule_id().c_str()));
		snprintf(request.get_fwrule.iface_id, sizeof(request.get_fwrule.iface_id),
				 "%s", request_.interface_id().c_str());
		snprintf(request.get_fwrule.rule_id, sizeof(request.get_fwrule.rule_id),
				 "%s", request_.rule_id().c_str());
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
		ConvertDPFWallRuleToGRPCFwallRule(&reply.fwrule.rule, rule);
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

void ListFirewallRulesCall::ListCallback(struct dpgrpc_reply *reply, void *context)
{
	struct dpgrpc_fwrule_info *grpc_rule;
	ListFirewallRulesResponse *reply_ = (ListFirewallRulesResponse *)context;
	FirewallRule *rule;

	if (reply->err_code) {
		reply_->set_allocated_status(CreateErrStatus(reply));
		return;
	}

	for (uint i = 0; i < reply->msg_count; ++i) {
		grpc_rule = DPGRPC_GET_MESSAGE(reply, i, struct dpgrpc_fwrule_info);
		rule = reply_->add_rules();
		ConvertDPFWallRuleToGRPCFwallRule(&grpc_rule->rule, rule);
	}
}

int ListFirewallRulesCall::Proceed()
{
	struct dpgrpc_request request = {
		.type = call_type_,
	};

	if (status_ == REQUEST) {
		new ListFirewallRulesCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		DPGRPC_LOG_DEBUG("Listing firewall rules",
						DP_LOG_IFACE(request_.interface_id().c_str()));
		snprintf(request.list_fwrule.iface_id, sizeof(request.list_fwrule.iface_id),
				 "%s", request_.interface_id().c_str());
		dp_send_to_worker(&request);  // TODO can fail
		status_ = AWAIT_MSG;
		return -1;
	} else if (status_ == INITCHECK) {
		responder_.Finish(reply_, ret, this);
		status_ = FINISH;
	} else if (status_ == AWAIT_MSG) {
		// TODO can fail hard (this `return -1` is only a wait loop)
		if (DP_FAILED(dp_recv_array_from_worker(ListCallback, &reply_, call_type_)))
			return -1;
		status_ = FINISH;
		responder_.Finish(reply_, ret, this);
	} else {
		GPR_ASSERT(status_ == FINISH);
		delete this;
	}
	return 0;
}

int GetVersionCall::Proceed()
{
	struct dpgrpc_request request = {
		.type = call_type_,
	};
	struct dpgrpc_reply reply;

	if (status_ == REQUEST) {
		new GetVersionCall(service_, cq_);
		if (InitCheck() == INITCHECK)
			return -1;
		DPGRPC_LOG_INFO("Getting version for client",
						DP_LOG_PROTOVER(request_.client_protocol().c_str()),
						DP_LOG_CLIENTNAME(request_.client_name().c_str()),
						DP_LOG_CLIENTVER(request_.client_version().c_str()));
		snprintf(request.get_version.proto, sizeof(request.get_version.proto),
				 "%s", request_.client_protocol().c_str());
		snprintf(request.get_version.name, sizeof(request.get_version.name),
				 "%s", request_.client_name().c_str());
		snprintf(request.get_version.app, sizeof(request.get_version.app),
				 "%s", request_.client_version().c_str());
		dp_send_to_worker(&request);  // TODO can fail
		status_ = AWAIT_MSG;
		return -1;
	} else if (status_ == INITCHECK) {
		responder_.Finish(reply_, ret, this);
		status_ = FINISH;
	} else if (status_ == AWAIT_MSG) {
		if (DP_FAILED(dp_recv_from_worker(&reply, call_type_)))  // TODO can fail (this `return -1` is only a wait loop)
			return -1;
		reply_.set_service_protocol(reply.versions.proto);
		reply_.set_service_version(reply.versions.app);
		status_ = FINISH;
		reply_.set_allocated_status(CreateErrStatus(&reply));
		responder_.Finish(reply_, ret, this);
	} else {
		GPR_ASSERT(status_ == FINISH);
		delete this;
	}
	return 0;
}
