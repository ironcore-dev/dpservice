// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#include "grpc/dp_async_grpc.h"
#include <arpa/inet.h>
#include <rte_ether.h>
#include <rte_mbuf.h>
#include "dp_log.h"
#include "dp_lpm.h"
#include "dp_util.h"
#include "grpc/dp_grpc_conv.h"
#include "grpc/dp_grpc_service.h"

// this is arbitrary, just not error or DP_OK
#define DP_GRPC_REPLY_NOT_READY 1

// Iterator for MultiReplyCall message array
#define FOREACH_MESSAGE(ITERATOR, REPLY) \
	for (ITERATOR = (typeof ITERATOR)(REPLY)->messages; \
		 ITERATOR < (typeof ITERATOR)(REPLY)->messages + (REPLY)->msg_count; \
		 ++ITERATOR)

// Prevent errors and large inputs (negative values/errors will be converted to huge size by uint)
#define SNPRINTF_FAILED(DEST, SRC) \
	((SRC).empty() || (uint)snprintf((DEST), sizeof(DEST), "%s", (SRC).c_str()) >= sizeof(DEST))


CallState BaseCall::HandleRpc()
{
	switch (call_state_) {
	case REQUEST: {
		struct dpgrpc_request request = {
			.type = call_type_,
		};
		const char* error;
		// this is how gRPC is implemented here,
		// one object per call type is always waiting in the queue (my understanding)
		// so, replace this object with a new one
		// see https://grpc.io/docs/languages/cpp/async/
		Clone();
		if (NeedsInit()) {
			Finish(grpc::Status(grpc::StatusCode::ABORTED, "not initialized"));
			call_state_ = FINISH;
		} else {
			error = FillRequest(&request);
			if (error) {
				Finish(grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, error));
				call_state_ = FINISH;
			} else if (DP_FAILED(WriteRequest(&request))) {
				Finish(grpc::Status(grpc::StatusCode::INTERNAL, "ipc write failed"));
				call_state_ = FINISH;
			} else
				call_state_ = AWAIT_MSG;
		}
		break;
	}
	case AWAIT_MSG: {
		int ret = HandleReply();
		if (DP_FAILED(ret)) {
			Finish(grpc::Status(grpc::StatusCode::INTERNAL, "reply parsing failed"));
			call_state_ = FINISH;
		} else if (ret == DP_OK) {
			Finish(grpc::Status::OK);
			call_state_ = FINISH;
		} else
			assert(ret == DP_GRPC_REPLY_NOT_READY);  // keep waiting
		break;
	}
	case FINISH:
		delete this;
		break;
	}
	return call_state_;
}

int BaseCall::WriteRequest(struct dpgrpc_request *request)
{
	struct rte_mbuf *m;
	int ret;

	m = rte_pktmbuf_alloc(get_dpdk_layer()->rte_mempool);
	if (!m) {
		DPGRPC_LOG_WARNING("Cannot allocate worker request", DP_LOG_GRPCREQUEST(request->type));
		return DP_ERROR;
	}

	assert((size_t)m->buf_len - m->data_off >= sizeof(struct dpgrpc_request));
	rte_memcpy(rte_pktmbuf_mtod(m, struct dpgrpc_request *), request, sizeof(*request));

	ret = rte_ring_sp_enqueue(get_dpdk_layer()->grpc_tx_queue, m);
	if (DP_FAILED(ret)) {
		DPGRPC_LOG_WARNING("Cannot enqueue worker request", DP_LOG_RET(ret), DP_LOG_GRPCREQUEST(request->type));
		rte_pktmbuf_free(m);
		return ret;
	}

	return DP_OK;
}

int SingleReplyCall::HandleReply()
{
	struct dpgrpc_reply *reply;
	struct rte_mbuf *m;
	int ret;

	ret = rte_ring_sc_dequeue(get_dpdk_layer()->grpc_rx_queue, (void **)&m);
	if (DP_FAILED(ret)) {
		if (ret == -ENOENT)
			return DP_GRPC_REPLY_NOT_READY;
		DPGRPC_LOG_WARNING("Cannot dequeue worker response", DP_LOG_RET(ret));
		return ret;
	}

	assert((size_t)m->buf_len - m->data_off >= sizeof(struct dpgrpc_reply));
	reply = rte_pktmbuf_mtod(m, struct dpgrpc_reply *);

	if (reply->type != call_type_) {
		DPGRPC_LOG_WARNING("Invalid response received", DP_LOG_GRPCREQUEST(call_type_));
		ret = DP_ERROR;
	} else if (reply->is_chained || reply->msg_count != 0) {
		DPGRPC_LOG_WARNING("Single response expected, multiresponse received", DP_LOG_GRPCREQUEST(call_type_));
		ret = DP_ERROR;
	} else {
		SetStatus(reply->err_code);
		if (reply->err_code == DP_GRPC_OK)
			ParseReply(reply);
	}

	rte_pktmbuf_free(m);
	return ret;
}

int MultiReplyCall::HandleReply()
{
	struct rte_mbuf *m;
	struct dpgrpc_reply *reply;
	uint8_t is_chained;
	int ret;

	do {
		ret = rte_ring_sc_dequeue(get_dpdk_layer()->grpc_rx_queue, (void **)&m);
		if (DP_FAILED(ret)) {
			if (ret == -ENOENT)
				return DP_GRPC_REPLY_NOT_READY;
			DPGRPC_LOG_WARNING("Cannot dequeue worker response", DP_LOG_RET(ret));
			return ret;
		}
		reply = rte_pktmbuf_mtod(m, struct dpgrpc_reply *);
		if (reply->type != call_type_) {
			DPGRPC_LOG_WARNING("Invalid response received", DP_LOG_GRPCREQUEST(call_type_));
			rte_pktmbuf_free(m);
			return DP_ERROR;
		}
		SetStatus(reply->err_code);
		if (reply->err_code == DP_GRPC_OK)
			ParseReply(reply);  // cannot stop on error here, chained replies need to be popped
		is_chained = reply->is_chained;
		rte_pktmbuf_free(m);
	} while (is_chained);

	return DP_OK;
}

int NoIpcCall::WriteRequest(__rte_unused struct dpgrpc_request *request)
{
	// no IPC, so no request needs to be filled here, do nothing
	return DP_OK;
}

int NoIpcCall::HandleReply()
{
	// no IPC, so no reading from worker, but reply status still needs to be filled
	SetStatus(DP_GRPC_OK);
	ParseReply(NULL);
	return DP_OK;
}


const char* InitializeCall::FillRequest(__rte_unused struct dpgrpc_request* request)
{
	DPGRPC_LOG_INFO("Initializing");
	return NULL;
}
void InitializeCall::ParseReply(__rte_unused struct dpgrpc_reply* reply)
{
	GRPCService::GetInstance()->SetInitStatus(true);
	reply_.set_uuid(service_->GetUUID());
}

const char* CheckInitializedCall::FillRequest(__rte_unused struct dpgrpc_request* request)
{
	return NULL;
}
void CheckInitializedCall::ParseReply(__rte_unused struct dpgrpc_reply* reply)
{
	// reply is actually NULL here
	reply_.set_uuid(service_->GetUUID());
}

const char* GetVersionCall::FillRequest(struct dpgrpc_request* request)
{
	DPGRPC_LOG_INFO("Getting version for client",
					DP_LOG_PROTOVER(request_.client_protocol().c_str()),
					DP_LOG_CLIENTNAME(request_.client_name().c_str()),
					DP_LOG_CLIENTVER(request_.client_version().c_str()));
	if (SNPRINTF_FAILED(request->get_version.proto, request_.client_protocol()))
		return "Invalid client_protocol";
	if (SNPRINTF_FAILED(request->get_version.name, request_.client_name()))
		return "Invalid client_name";
	if (SNPRINTF_FAILED(request->get_version.app, request_.client_version()))
		return "Invalid client_version";
	return NULL;
}
void GetVersionCall::ParseReply(struct dpgrpc_reply* reply)
{
	reply_.set_service_protocol(reply->versions.proto);
	reply_.set_service_version(reply->versions.app);
}


const char* CreateInterfaceCall::FillRequest(struct dpgrpc_request* request)
{
	DPGRPC_LOG_INFO("Adding interface",
					DP_LOG_IFACE(request_.interface_id().c_str()),
					DP_LOG_VNI(request_.vni()),
					DP_LOG_IPV4STR(request_.ipv4_config().primary_address().c_str()),
					DP_LOG_IPV6STR(request_.ipv6_config().primary_address().c_str()),
					DP_LOG_PCI(request_.device_name().c_str()),
					DP_LOG_METER_TOTAL(request_.metering_parameters().total_rate()),
					DP_LOG_METER_PUBLIC(request_.metering_parameters().public_rate()));
	if (!GrpcConv::IsInterfaceIdValid(request_.interface_id()))
		return "Invalid interface_id";
	request->add_iface.vni = request_.vni();
	if (!GrpcConv::StrToIpv4(request_.ipv4_config().primary_address(), &request->add_iface.ip4_addr))
		return "Invalid ipv4_config.primary_address";
	if (!GrpcConv::StrToIpv6(request_.ipv6_config().primary_address(), &request->add_iface.ip6_addr))
		return "Invalid ipv6_config.primary_address";
	if (request->add_iface.ip4_addr == 0 && dp_is_ipv6_zero(&request->add_iface.ip6_addr))
		return "Invalid ipv4_config.primary_address and ipv6_config.primary_address combination";
	if (!request_.pxe_config().next_server().empty()) {
		DPGRPC_LOG_INFO("Setting PXE",
						DP_LOG_IFACE(request_.interface_id().c_str()),
						DP_LOG_PXE_SRV(request_.pxe_config().next_server().c_str()),
						DP_LOG_PXE_PATH(request_.pxe_config().boot_filename().c_str()));
		if (!GrpcConv::StrToDpAddress(request_.pxe_config().next_server(), &request->add_iface.pxe_addr,
			dp_is_ipv6_zero(&request->add_iface.ip6_addr) ? IpVersion::IPV4 : IpVersion::IPV6))
			return "Invalid pxe_config.next_server";
		if (SNPRINTF_FAILED(request->add_iface.pxe_str, request_.pxe_config().boot_filename()))
			return "Invalid pxe_config.boot_filename";
	}
	if (SNPRINTF_FAILED(request->add_iface.pci_name, request_.device_name()))
		return "Invalid device_name";
	if (SNPRINTF_FAILED(request->add_iface.iface_id, request_.interface_id()))
		return "Invalid interface_id";

	request->add_iface.total_flow_rate_cap = request_.metering_parameters().total_rate();
	request->add_iface.public_flow_rate_cap = request_.metering_parameters().public_rate();

	return NULL;
}
void CreateInterfaceCall::ParseReply(struct dpgrpc_reply* reply)
{
	VirtualFunction *vf;
	char strbuf[INET6_ADDRSTRLEN];

	vf = new VirtualFunction();
	vf->set_name(reply->vf_pci.name);
	reply_.set_allocated_vf(vf);
	DP_IPV6_TO_STR(&reply->vf_pci.ul_addr6, strbuf);
	reply_.set_underlay_route(strbuf);
}

const char* DeleteInterfaceCall::FillRequest(struct dpgrpc_request* request)
{
	DPGRPC_LOG_INFO("Removing interface",
					DP_LOG_IFACE(request_.interface_id().c_str()));
	if (SNPRINTF_FAILED(request->del_iface.iface_id, request_.interface_id()))
		return "Invalid interface_id";
	return NULL;
}
void DeleteInterfaceCall::ParseReply(__rte_unused struct dpgrpc_reply* reply)
{
}

const char* GetInterfaceCall::FillRequest(struct dpgrpc_request* request)
{
	DPGRPC_LOG_INFO("Getting interface info",
					DP_LOG_IFACE(request_.interface_id().c_str()));
	if (SNPRINTF_FAILED(request->get_iface.iface_id, request_.interface_id()))
		return "Invalid interface_id";
	return NULL;
}
void GetInterfaceCall::ParseReply(struct dpgrpc_reply* reply)
{
	Interface *grpc_iface;

	grpc_iface = new Interface();
	GrpcConv::DpToGrpcInterface(&reply->iface, grpc_iface);
	reply_.set_allocated_interface(grpc_iface);
}

const char* ListInterfacesCall::FillRequest(__rte_unused struct dpgrpc_request* request)
{
	DPGRPC_LOG_INFO("Listing interfaces");
	return NULL;
}
void ListInterfacesCall::ParseReply(struct dpgrpc_reply* reply)
{
	struct dpgrpc_iface *dp_iface;
	Interface *grpc_iface;

	FOREACH_MESSAGE(dp_iface, reply) {
		grpc_iface = reply_.add_interfaces();
		GrpcConv::DpToGrpcInterface(dp_iface, grpc_iface);
	}
}


const char* CreatePrefixCall::FillRequest(struct dpgrpc_request* request)
{
	DPGRPC_LOG_INFO("Adding alias prefix",
					DP_LOG_IFACE(request_.interface_id().c_str()),
					DP_LOG_PREFIX(request_.prefix().ip().address().c_str()),
					DP_LOG_PREFLEN(request_.prefix().length()));
	if (SNPRINTF_FAILED(request->add_pfx.iface_id, request_.interface_id()))
		return "Invalid interface_id";
	if (!GrpcConv::GrpcToDpAddress(request_.prefix().ip(), &request->del_pfx.addr))
		return "Invalid prefix.ip";
	if (request_.prefix().length() > UINT8_MAX)
		return "Invalid prefix.length";
	request->del_pfx.length = (uint8_t)request_.prefix().length();
	return NULL;
}
void CreatePrefixCall::ParseReply(struct dpgrpc_reply* reply)
{
	char strbuf[INET6_ADDRSTRLEN];

	DP_IPV6_TO_STR(&reply->ul_addr.addr6, strbuf);
	reply_.set_underlay_route(strbuf);
}

const char* DeletePrefixCall::FillRequest(struct dpgrpc_request* request)
{
	DPGRPC_LOG_INFO("Removing alias prefix",
					DP_LOG_IFACE(request_.interface_id().c_str()),
					DP_LOG_PREFIX(request_.prefix().ip().address().c_str()),
					DP_LOG_PREFLEN(request_.prefix().length()));
	if (SNPRINTF_FAILED(request->del_pfx.iface_id, request_.interface_id()))
		return "Invalid interface_id";
	if (!GrpcConv::GrpcToDpAddress(request_.prefix().ip(), &request->del_pfx.addr))
		return "Invalid prefix.ip";
	if (request_.prefix().length() > UINT8_MAX)
		return "Invalid prefix.length";
	request->del_pfx.length = (uint8_t)request_.prefix().length();
	return NULL;
}
void DeletePrefixCall::ParseReply(__rte_unused struct dpgrpc_reply* reply)
{
}

const char* ListPrefixesCall::FillRequest(struct dpgrpc_request* request)
{
	DPGRPC_LOG_INFO("Listing alias prefixes",
					DP_LOG_IFACE(request_.interface_id().c_str()));
	if (SNPRINTF_FAILED(request->list_pfx.iface_id, request_.interface_id()))
		return "Invalid interface_id";
	return NULL;
}
void ListPrefixesCall::ParseReply(struct dpgrpc_reply* reply)
{
	struct dpgrpc_route *route;
	Prefix *pfx;
	IpAddress *pfx_ip;
	char strbuf[INET6_ADDRSTRLEN];

	FOREACH_MESSAGE(route, reply) {
		pfx = reply_.add_prefixes();
		pfx_ip = new IpAddress();
		GrpcConv::DpToGrpcAddress(&route->pfx_addr, pfx_ip);
		pfx->set_length(route->pfx_length);
		DP_IPADDR_TO_STR(&route->trgt_addr, strbuf);
		pfx->set_underlay_route(strbuf);
		pfx->set_allocated_ip(pfx_ip);
	}
}


const char* CreateRouteCall::FillRequest(struct dpgrpc_request* request)
{
	DPGRPC_LOG_INFO("Adding route",
					DP_LOG_VNI(request_.vni()),
					DP_LOG_PREFIX(request_.route().prefix().ip().address().c_str()),
					DP_LOG_PREFLEN(request_.route().prefix().length()),
					DP_LOG_TVNI(request_.route().nexthop_vni()),
					DP_LOG_IPV6STR(request_.route().nexthop_address().address().c_str()));
	request->add_route.vni = request_.vni();
	request->add_route.trgt_vni = request_.route().nexthop_vni();
	if (request_.route().prefix().length() > UINT8_MAX)
		return "Invalid route.prefix.length";
	request->add_route.pfx_length = (uint8_t)request_.route().prefix().length();
	if (!GrpcConv::GrpcToDpAddress(request_.route().prefix().ip(), &request->add_route.pfx_addr))
		return "Invalid route.prefix.ip";
	if (!GrpcConv::GrpcToDpAddress(request_.route().nexthop_address(), &request->add_route.trgt_addr))
		return "Invalid route.nexthop_address";
	return NULL;
}
void CreateRouteCall::ParseReply(__rte_unused struct dpgrpc_reply* reply)
{
}

const char* DeleteRouteCall::FillRequest(struct dpgrpc_request* request)
{
	DPGRPC_LOG_INFO("Removing route",
					DP_LOG_VNI(request_.vni()),
					DP_LOG_PREFIX(request_.route().prefix().ip().address().c_str()),
					DP_LOG_PREFLEN(request_.route().prefix().length()));
	request->del_route.vni = request_.vni();
	if (request_.route().prefix().length() > UINT8_MAX)
		return "Invalid route.prefix.length";
	request->add_route.pfx_length = (uint8_t)request_.route().prefix().length();
	if (!GrpcConv::GrpcToDpAddress(request_.route().prefix().ip(), &request->add_route.pfx_addr))
		return "Invalid route.prefix.ip";
	return NULL;
}
void DeleteRouteCall::ParseReply(__rte_unused struct dpgrpc_reply* reply)
{
}

const char* ListRoutesCall::FillRequest(struct dpgrpc_request* request)
{
	DPGRPC_LOG_INFO("Listing routes",
					DP_LOG_VNI(request_.vni()));
	request->list_route.vni = request_.vni();
	request->list_route.type = DP_VNI_BOTH;
	return NULL;
}
void ListRoutesCall::ParseReply(struct dpgrpc_reply* reply)
{
	struct dpgrpc_route *route;
	Route *grpc_route;
	IpAddress *nh_ip;
	Prefix *pfx;
	IpAddress *pfx_ip;

	FOREACH_MESSAGE(route, reply) {
		grpc_route = reply_.add_routes();
		grpc_route->set_nexthop_vni(route->trgt_vni);

		nh_ip = new IpAddress();
		GrpcConv::DpToGrpcAddress(&route->trgt_addr, nh_ip);
		grpc_route->set_allocated_nexthop_address(nh_ip);

		pfx_ip = new IpAddress();
		GrpcConv::DpToGrpcAddress(&route->pfx_addr, pfx_ip);

		pfx = new Prefix();
		pfx->set_allocated_ip(pfx_ip);
		pfx->set_length(route->pfx_length);
		grpc_route->set_allocated_prefix(pfx);
	}
}


const char* CreateVipCall::FillRequest(struct dpgrpc_request* request)
{
	DPGRPC_LOG_INFO("Setting virtual IP",
					DP_LOG_IFACE(request_.interface_id().c_str()),
					DP_LOG_IPV4STR(request_.vip_ip().address().c_str()));
	if (SNPRINTF_FAILED(request->add_vip.iface_id, request_.interface_id()))
		return "Invalid interface_id";
	if (!GrpcConv::GrpcToDpAddress(request_.vip_ip(), &request->add_vip.addr))
		return "Invalid vip_ip";
	return NULL;
}
void CreateVipCall::ParseReply(struct dpgrpc_reply* reply)
{
	char strbuf[INET6_ADDRSTRLEN];

	DP_IPV6_TO_STR(&reply->ul_addr.addr6, strbuf);
	reply_.set_underlay_route(strbuf);
}

const char* DeleteVipCall::FillRequest(struct dpgrpc_request* request)
{
	DPGRPC_LOG_INFO("Removing virtual IP",
					DP_LOG_IFACE(request_.interface_id().c_str()));
	if (SNPRINTF_FAILED(request->del_vip.iface_id, request_.interface_id()))
		return "Invalid interface_id";
	return NULL;
}
void DeleteVipCall::ParseReply(__rte_unused struct dpgrpc_reply* reply)
{
}

const char* GetVipCall::FillRequest(struct dpgrpc_request* request)
{
	DPGRPC_LOG_INFO("Getting virtual IP",
					DP_LOG_IFACE(request_.interface_id().c_str()));
	if (SNPRINTF_FAILED(request->get_vip.iface_id, request_.interface_id()))
		return "Invalid interface_id";
	return NULL;
}
void GetVipCall::ParseReply(struct dpgrpc_reply* reply)
{
	IpAddress *vip_ip;
	char strbuf[INET6_ADDRSTRLEN];

	vip_ip = new IpAddress();
	GrpcConv::DpToGrpcAddress(&reply->vip.addr, vip_ip);
	DP_IPV6_TO_STR(&reply->vip.ul_addr6, strbuf);
	reply_.set_allocated_vip_ip(vip_ip);
	reply_.set_underlay_route(strbuf);
}


const char* CreateNatCall::FillRequest(struct dpgrpc_request* request)
{
	DPGRPC_LOG_INFO("Setting NAT IP",
					DP_LOG_IFACE(request_.interface_id().c_str()),
					DP_LOG_IPV4STR(request_.nat_ip().address().c_str()),
					DP_LOG_MINPORT(request_.min_port()),
					DP_LOG_MAXPORT(request_.max_port()));
	if (SNPRINTF_FAILED(request->add_nat.iface_id, request_.interface_id()))
		return "Invalid interface_id";
	if (!GrpcConv::GrpcToDpAddress(request_.nat_ip(), &request->add_nat.addr))
		return "Invalid nat_ip";
	if (request_.min_port() > UINT16_MAX)
		return "Invalid min_port";
	if (request_.max_port() > UINT16_MAX)
		return "Invalid max_port";
	if (request_.min_port() >= request_.max_port())
		return "Invalid port range";
	request->add_nat.min_port = (uint16_t)request_.min_port();
	request->add_nat.max_port = (uint16_t)request_.max_port();
	return NULL;
}
void CreateNatCall::ParseReply(struct dpgrpc_reply* reply)
{
	char strbuf[INET6_ADDRSTRLEN];

	DP_IPV6_TO_STR(&reply->ul_addr.addr6, strbuf);
	reply_.set_underlay_route(strbuf);
}

const char* GetNatCall::FillRequest(struct dpgrpc_request* request)
{
	DPGRPC_LOG_INFO("Getting NAT IP",
					DP_LOG_IFACE(request_.interface_id().c_str()));
	if (SNPRINTF_FAILED(request->get_vip.iface_id, request_.interface_id()))
		return "Invalid interface_id";
	return NULL;
}
void GetNatCall::ParseReply(struct dpgrpc_reply* reply)
{
	IpAddress *nat_ip;
	char strbuf[INET6_ADDRSTRLEN];

	nat_ip = new IpAddress();
	GrpcConv::DpToGrpcAddress(&reply->nat.addr, nat_ip);
	reply_.set_allocated_nat_ip(nat_ip);
	reply_.set_max_port(reply->nat.max_port);
	reply_.set_min_port(reply->nat.min_port);
	DP_IPV6_TO_STR(&reply->nat.ul_addr6, strbuf);
	reply_.set_underlay_route(strbuf);
}

const char* DeleteNatCall::FillRequest(struct dpgrpc_request* request)
{
	DPGRPC_LOG_INFO("Removing NAT IP",
					DP_LOG_IFACE(request_.interface_id().c_str()));
	if (SNPRINTF_FAILED(request->del_nat.iface_id, request_.interface_id()))
		return "Invalid interface_id";
	return NULL;
}
void DeleteNatCall::ParseReply(__rte_unused struct dpgrpc_reply* reply)
{
}

const char* ListLocalNatsCall::FillRequest(struct dpgrpc_request* request)
{
	DPGRPC_LOG_INFO("Listing local Nats",
					DP_LOG_IPV4STR(request_.nat_ip().address().c_str()));
	if (!GrpcConv::GrpcToDpAddress(request_.nat_ip(), &request->list_localnat))
		return "Invalid nat_ip";
	return NULL;
}
void ListLocalNatsCall::ParseReply(struct dpgrpc_reply* reply)
{
	struct dpgrpc_nat *nat;
	NatEntry *nat_entry;
	IpAddress *natted_ip;
	IpAddress *nat_ip;

	FOREACH_MESSAGE(nat, reply) {
		nat_entry = reply_.add_nat_entries();
		natted_ip = new IpAddress();
		GrpcConv::DpToGrpcAddress(&nat->natted_ip, natted_ip);
		nat_entry->set_allocated_nat_ip(natted_ip);
		nat_entry->set_min_port(nat->min_port);
		nat_entry->set_max_port(nat->max_port);
		nat_entry->set_vni(nat->vni);
		nat_ip = new IpAddress();
		GrpcConv::DpToGrpcAddress(&nat->addr, nat_ip);
		nat_entry->set_allocated_actual_nat_ip(nat_ip);
	}
}

const char* CreateNeighborNatCall::FillRequest(struct dpgrpc_request* request)
{
	DPGRPC_LOG_INFO("Adding neighboring NAT",
					DP_LOG_VNI(request_.vni()),
					DP_LOG_IPV4STR(request_.nat_ip().address().c_str()),
					DP_LOG_MINPORT(request_.min_port()),
					DP_LOG_MAXPORT(request_.max_port()),
					DP_LOG_IPV6STR(request_.underlay_route().c_str()));
	if (!GrpcConv::GrpcToDpAddress(request_.nat_ip(), &request->add_neighnat.addr))
		return "Invalid nat_ip";
	if (request_.min_port() > UINT16_MAX)
		return "Invalid min_port";
	if (request_.max_port() > UINT16_MAX)
		return "Invalid max_port";
	if (request_.min_port() >= request_.max_port())
		return "Invalid port range";
	request->add_neighnat.min_port = (uint16_t)request_.min_port();
	request->add_neighnat.max_port = (uint16_t)request_.max_port();
	request->add_neighnat.vni = request_.vni();
	if (!GrpcConv::StrToIpv6(request_.underlay_route(), &request->add_neighnat.neigh_addr6))
		return "Invalid underlay_route";
	return NULL;
}
void CreateNeighborNatCall::ParseReply(__rte_unused struct dpgrpc_reply* reply)
{
}

const char* DeleteNeighborNatCall::FillRequest(struct dpgrpc_request* request)
{
	DPGRPC_LOG_INFO("Removing neighboring NAT",
					DP_LOG_VNI(request_.vni()),
					DP_LOG_IPV4STR(request_.nat_ip().address().c_str()),
					DP_LOG_MINPORT(request_.min_port()),
					DP_LOG_MAXPORT(request_.max_port()));
	if (!GrpcConv::GrpcToDpAddress(request_.nat_ip(), &request->add_neighnat.addr))
		return "Invalid nat_ip";
	if (request_.min_port() > UINT16_MAX)
		return "Invalid min_port";
	if (request_.max_port() > UINT16_MAX)
		return "Invalid max_port";
	if (request_.min_port() >= request_.max_port())
		return "Invalid port range";
	request->del_neighnat.min_port = (uint16_t)request_.min_port();
	request->del_neighnat.max_port = (uint16_t)request_.max_port();
	request->del_neighnat.vni = request_.vni();
	// neigh_addr6 field is implied by this unique NAT definition
	return NULL;
}
void DeleteNeighborNatCall::ParseReply(__rte_unused struct dpgrpc_reply* reply)
{
}

const char* ListNeighborNatsCall::FillRequest(struct dpgrpc_request* request)
{
	DPGRPC_LOG_INFO("Listing neighbor Nats",
					DP_LOG_IPV4STR(request_.nat_ip().address().c_str()));
	if (!GrpcConv::GrpcToDpAddress(request_.nat_ip(), &request->list_localnat))
		return "Invalid nat_ip";
	return NULL;
}
void ListNeighborNatsCall::ParseReply(struct dpgrpc_reply* reply)
{
	struct dpgrpc_nat *nat;
	NatEntry *nat_entry;
	IpAddress *nat_ip;
	char strbuf[INET6_ADDRSTRLEN];

	FOREACH_MESSAGE(nat, reply) {
		nat_entry = reply_.add_nat_entries();
		DP_IPV6_TO_STR(&nat->ul_addr6, strbuf);
		nat_entry->set_underlay_route(strbuf);
		nat_entry->set_min_port(nat->min_port);
		nat_entry->set_max_port(nat->max_port);
		nat_entry->set_vni(nat->vni);
		nat_ip = new IpAddress();
		GrpcConv::DpToGrpcAddress(&nat->addr, nat_ip);
		nat_entry->set_allocated_actual_nat_ip(nat_ip);
	}
}


const char* CreateLoadBalancerCall::FillRequest(struct dpgrpc_request* request)
{
	uint8_t proto;
	uint16_t port;

	DPGRPC_LOG_INFO("Creating loadbalancer",
					DP_LOG_LBID(request_.loadbalancer_id().c_str()),
					DP_LOG_VNI(request_.vni()),
					DP_LOG_IPV4STR(request_.loadbalanced_ip().address().c_str()));
	if (SNPRINTF_FAILED(request->add_lb.lb_id, request_.loadbalancer_id()))
		return "Invalid loadbalancer_id";
	request->add_lb.vni = request_.vni();
	if (!GrpcConv::GrpcToDpAddress(request_.loadbalanced_ip(), &request->add_lb.addr))
		return "Invalid loadbalanced_ip";
	if (request_.loadbalanced_ports_size() >= DP_LB_MAX_PORTS)
		return "Too many loadbalanced_ports";
	for (int i = 0; i < request_.loadbalanced_ports_size(); ++i) {
		DPGRPC_LOG_INFO("Adding loadbalanced port",
						DP_LOG_LBID(request_.loadbalancer_id().c_str()),
						DP_LOG_L4PORT(request_.loadbalanced_ports(i).port()),
						DP_LOG_PROTO(request_.loadbalanced_ports(i).protocol()));
		if (request_.loadbalanced_ports(i).port() > UINT16_MAX)
			return "Invalid loadbalanced_ports.port";
		port = (uint16_t)request_.loadbalanced_ports(i).port();
		if (request_.loadbalanced_ports(i).protocol() == TCP)
			proto = IPPROTO_TCP;
		else if (request_.loadbalanced_ports(i).protocol() == UDP)
			proto = IPPROTO_UDP;
		else
			return "Invalid loadbalanced_ports.protocol";
		for (int j = 0; j < i; ++j) {
			if (request->add_lb.lbports[j].protocol == proto && request->add_lb.lbports[j].port == port)
				return "Duplicate loadbalanced_ports entry";
		}
		request->add_lb.lbports[i].port = port;
		request->add_lb.lbports[i].protocol = proto;
	}
	return NULL;
}
void CreateLoadBalancerCall::ParseReply(struct dpgrpc_reply* reply)
{
	char strbuf[INET6_ADDRSTRLEN];

	DP_IPV6_TO_STR(&reply->ul_addr.addr6, strbuf);
	reply_.set_underlay_route(strbuf);
}

const char* DeleteLoadBalancerCall::FillRequest(struct dpgrpc_request* request)
{
	DPGRPC_LOG_INFO("Removing loadbalancer",
					DP_LOG_LBID(request_.loadbalancer_id().c_str()));
	if (SNPRINTF_FAILED(request->del_lb.lb_id, request_.loadbalancer_id()))
		return "Invalid loadbalancer_id";
	return NULL;
}
void DeleteLoadBalancerCall::ParseReply(__rte_unused struct dpgrpc_reply* reply)
{
}

const char* GetLoadBalancerCall::FillRequest(struct dpgrpc_request* request)
{
	DPGRPC_LOG_INFO("Getting loadbalancer info",
					DP_LOG_LBID(request_.loadbalancer_id().c_str()));
	if (SNPRINTF_FAILED(request->get_lb.lb_id, request_.loadbalancer_id()))
		return "Invalid loadbalancer_id";
	return NULL;
}
void GetLoadBalancerCall::ParseReply(struct dpgrpc_reply* reply)
{
	LbPort *lb_port;
	IpAddress *lb_ip;
	char strbuf[INET6_ADDRSTRLEN];

	reply_.set_vni(reply->lb.vni);
	lb_ip = new IpAddress();
	GrpcConv::DpToGrpcAddress(&reply->lb.addr, lb_ip);
	reply_.set_allocated_loadbalanced_ip(lb_ip);
	for (int i = 0; i < DP_LB_MAX_PORTS; ++i) {
		if (reply->lb.lbports[i].port == 0)
			continue;
		lb_port = reply_.add_loadbalanced_ports();
		lb_port->set_port(reply->lb.lbports[i].port);
		if (reply->lb.lbports[i].protocol == IPPROTO_TCP)
			lb_port->set_protocol(TCP);
		if (reply->lb.lbports[i].protocol == IPPROTO_UDP)
			lb_port->set_protocol(UDP);
	}
	DP_IPV6_TO_STR(&reply->lb.ul_addr6, strbuf);
	reply_.set_underlay_route(strbuf);
}

const char* ListLoadBalancersCall::FillRequest(__rte_unused struct dpgrpc_request* request)
{
	DPGRPC_LOG_INFO("Listing loadbalancers");
	return NULL;
}
void ListLoadBalancersCall::ParseReply(struct dpgrpc_reply* reply)
{
	struct dpgrpc_lb *dp_lb;
	Loadbalancer *grpc_lb;

	FOREACH_MESSAGE(dp_lb, reply) {
		grpc_lb = reply_.add_loadbalancers();
		// TODO GetLoadBalancerCall should use this in the future
		// (it's currently not as to not break backward-compatibility)
		GrpcConv::DpToGrpcLoadBalancer(dp_lb, grpc_lb);
	}
}



const char* CreateLoadBalancerTargetCall::FillRequest(struct dpgrpc_request* request)
{
	DPGRPC_LOG_INFO("Adding loadbalancer target",
					DP_LOG_LBID(request_.loadbalancer_id().c_str()),
					DP_LOG_IPV6STR(request_.target_ip().address().c_str()));
	if (SNPRINTF_FAILED(request->add_lbtrgt.lb_id, request_.loadbalancer_id()))
		return "Invalid loadbalancer_id";
	if (!GrpcConv::GrpcToDpAddress(request_.target_ip(), &request->add_lbtrgt.addr))
		return "Invalid target_ip";
	return NULL;
}
void CreateLoadBalancerTargetCall::ParseReply(__rte_unused struct dpgrpc_reply* reply)
{
}

const char* DeleteLoadBalancerTargetCall::FillRequest(struct dpgrpc_request* request)
{
	DPGRPC_LOG_INFO("Removing loadbalancer target",
					DP_LOG_LBID(request_.loadbalancer_id().c_str()),
					DP_LOG_IPV6STR(request_.target_ip().address().c_str()));
	if (SNPRINTF_FAILED(request->del_lbtrgt.lb_id, request_.loadbalancer_id()))
		return "Invalid loadbalancer_id";
	if (!GrpcConv::GrpcToDpAddress(request_.target_ip(), &request->del_lbtrgt.addr))
		return "Invalid target_ip";
	return NULL;
}
void DeleteLoadBalancerTargetCall::ParseReply(__rte_unused struct dpgrpc_reply* reply)
{
}

const char* ListLoadBalancerTargetsCall::FillRequest(struct dpgrpc_request* request)
{
	DPGRPC_LOG_INFO("Listing loadbalancer targets",
					DP_LOG_LBID(request_.loadbalancer_id().c_str()));
	if (SNPRINTF_FAILED(request->list_lbtrgt.lb_id, request_.loadbalancer_id()))
		return "Invalid loadbalancer_id";
	return NULL;
}
void ListLoadBalancerTargetsCall::ParseReply(struct dpgrpc_reply* reply)
{
	struct dpgrpc_lb_target *lb_target;
	IpAddress *target_ip;

	FOREACH_MESSAGE(lb_target, reply) {
		target_ip = reply_.add_target_ips();
		GrpcConv::DpToGrpcAddress(&lb_target->addr, target_ip);
	}
}


const char* CreateLoadBalancerPrefixCall::FillRequest(struct dpgrpc_request* request)
{
	DPGRPC_LOG_INFO("Adding loadbalancer target prefix",
					DP_LOG_IFACE(request_.interface_id().c_str()),
					DP_LOG_PREFIX(request_.prefix().ip().address().c_str()),
					DP_LOG_PREFLEN(request_.prefix().length()));
	if (SNPRINTF_FAILED(request->add_lbpfx.iface_id, request_.interface_id()))
		return "Invalid interface_id";
	if (!GrpcConv::GrpcToDpAddress(request_.prefix().ip(), &request->add_lbpfx.addr))
		return "Invalid prefix.ip";
	if (request_.prefix().length() > UINT8_MAX)
		return "Invalid prefix.length";
	request->add_lbpfx.length = (uint8_t)request_.prefix().length();
	return NULL;
}
void CreateLoadBalancerPrefixCall::ParseReply(struct dpgrpc_reply* reply)
{
	char strbuf[INET6_ADDRSTRLEN];

	DP_IPADDR_TO_STR(&reply->route.trgt_addr, strbuf);
	reply_.set_underlay_route(strbuf);
}

const char* DeleteLoadBalancerPrefixCall::FillRequest(struct dpgrpc_request* request)
{
	DPGRPC_LOG_INFO("Removing loadbalancer target prefix",
					DP_LOG_IFACE(request_.interface_id().c_str()),
					DP_LOG_PREFIX(request_.prefix().ip().address().c_str()),
					DP_LOG_PREFLEN(request_.prefix().length()));
	if (SNPRINTF_FAILED(request->del_lbpfx.iface_id, request_.interface_id()))
		return "Invalid interface_id";
	if (!GrpcConv::GrpcToDpAddress(request_.prefix().ip(), &request->del_lbpfx.addr))
		return "Invalid prefix.ip";
	if (request_.prefix().length() > UINT8_MAX)
		return "Invalid prefix.length";
	request->del_lbpfx.length = (uint8_t)request_.prefix().length();
	return NULL;
}
void DeleteLoadBalancerPrefixCall::ParseReply(__rte_unused struct dpgrpc_reply* reply)
{
}

const char* ListLoadBalancerPrefixesCall::FillRequest(struct dpgrpc_request* request)
{
	DPGRPC_LOG_INFO("Listing loadbalancer target prefixes",
					DP_LOG_IFACE(request_.interface_id().c_str()));
	if (SNPRINTF_FAILED(request->list_lbpfx.iface_id, request_.interface_id()))
		return "Invalid interface_id";
	return NULL;
}
void ListLoadBalancerPrefixesCall::ParseReply(struct dpgrpc_reply* reply)
{
	struct dpgrpc_route *route;
	Prefix *pfx;
	IpAddress *pfx_ip;
	char strbuf[INET6_ADDRSTRLEN];

	FOREACH_MESSAGE(route, reply) {
		pfx = reply_.add_prefixes();
		pfx_ip = new IpAddress();
		GrpcConv::DpToGrpcAddress(&route->pfx_addr, pfx_ip);
		pfx->set_length(route->pfx_length);
		DP_IPADDR_TO_STR(&route->trgt_addr, strbuf);
		pfx->set_underlay_route(strbuf);
		pfx->set_allocated_ip(pfx_ip);
	}
}


const char* CreateFirewallRuleCall::FillRequest(struct dpgrpc_request* request)
{
	const FirewallRule& grpc_rule = request_.rule();
	const ProtocolFilter& grpc_filter = grpc_rule.protocol_filter();
	struct dp_fwall_rule *dp_rule = &request->add_fwrule.rule;
	struct dp_port_filter *dp_ports = &dp_rule->filter.tcp_udp;

	DPGRPC_LOG_INFO("Adding firewall rule",
					DP_LOG_IFACE(request_.interface_id().c_str()),
					DP_LOG_FWRULE(grpc_rule.id().c_str()),
					DP_LOG_FWPRIO(grpc_rule.priority()),
					DP_LOG_FWDIR(grpc_rule.direction()),
					DP_LOG_FWACTION(grpc_rule.action()),
					DP_LOG_FWSRC(grpc_rule.source_prefix().ip().address().c_str()),
					DP_LOG_FWSRCLEN(grpc_rule.source_prefix().length()),
					DP_LOG_FWDST(grpc_rule.destination_prefix().ip().address().c_str()),
					DP_LOG_FWDSTLEN(grpc_rule.destination_prefix().length()));
	if (SNPRINTF_FAILED(request->add_fwrule.iface_id, request_.interface_id()))
		return "Invalid interface_id";
	if (SNPRINTF_FAILED(dp_rule->rule_id, grpc_rule.id()))
		return "Invalid rule id";
	if (grpc_rule.source_prefix().ip().ipver() != IpVersion::IPV4 && grpc_rule.source_prefix().ip().ipver() != IpVersion::IPV6)
		return "Invalid source_prefix.ip.ipver";
	if (!GrpcConv::GrpcToDpAddress(grpc_rule.source_prefix().ip(), &dp_rule->src_ip))
		return "Invalid source_prefix.ip";
	if (grpc_rule.source_prefix().ip().ipver() == IpVersion::IPV4) {
		if (!GrpcConv::Ipv4PrefixLenToMask(grpc_rule.source_prefix().length(), &dp_rule->src_mask))
			return "Invalid source_prefix.length";
	} else {
		if (!GrpcConv::Ipv6PrefixLenToMask(grpc_rule.source_prefix().length(), &dp_rule->src_mask))
			return "Invalid ip6 source_prefix.length";
	}
	if (grpc_rule.destination_prefix().ip().ipver() != IpVersion::IPV4 && grpc_rule.destination_prefix().ip().ipver() != IpVersion::IPV6)
		return "Invalid destination_prefix.ip.ipver";
	if (!GrpcConv::GrpcToDpAddress(grpc_rule.destination_prefix().ip(), &dp_rule->dest_ip))
		return "Invalid destination_prefix.ip";
	if (grpc_rule.destination_prefix().ip().ipver() == IpVersion::IPV4) {
		if (!GrpcConv::Ipv4PrefixLenToMask(grpc_rule.destination_prefix().length(), &dp_rule->dest_mask))
			return "Invalid destination_prefix.length";
	} else {
		if (!GrpcConv::Ipv6PrefixLenToMask(grpc_rule.destination_prefix().length(), &dp_rule->dest_mask))
			return "Invalid ip6 destination_prefix.length";
	}
	if (!GrpcConv::GrpcToDpFwallDirection(grpc_rule.direction(), &dp_rule->dir))
		return "Invalid direction";
	if (!GrpcConv::GrpcToDpFwallAction(grpc_rule.action(), &dp_rule->action))
		return "Invalid action";
	if (grpc_rule.priority() > UINT16_MAX)
		return "Invalid priority";
	dp_rule->priority = (uint16_t)grpc_rule.priority();

	switch (grpc_filter.filter_case()) {
	case ProtocolFilter::kTcpFieldNumber:
		DPGRPC_LOG_INFO("Adding firewall rule filter",
						DP_LOG_FWRULE(grpc_rule.id().c_str()),
						DP_LOG_FWPROTO(IPPROTO_TCP),
						DP_LOG_FWSPORTFROM(grpc_filter.tcp().src_port_lower()),
						DP_LOG_FWSPORTTO(grpc_filter.tcp().src_port_upper()),
						DP_LOG_FWDPORTFROM(grpc_filter.tcp().dst_port_lower()),
						DP_LOG_FWDPORTTO(grpc_filter.tcp().dst_port_upper()));
		dp_rule->protocol = IPPROTO_TCP;
		if (!GrpcConv::GrpcToDpFwallPort(grpc_filter.tcp().src_port_lower(), &dp_ports->src_port.lower))
			return "Invalid tcp.src_port_lower";
		if (!GrpcConv::GrpcToDpFwallPort(grpc_filter.tcp().dst_port_lower(), &dp_ports->dst_port.lower))
			return "Invalid tcp.dst_port_lower";
		if (!GrpcConv::GrpcToDpFwallPort(grpc_filter.tcp().src_port_upper(), &dp_ports->src_port.upper))
			return "Invalid tcp.src_port_upper";
		if (!GrpcConv::GrpcToDpFwallPort(grpc_filter.tcp().dst_port_upper(), &dp_ports->dst_port.upper))
			return "Invalid tcp.dst_port_upper";
		if (dp_ports->src_port.lower != DP_FWALL_MATCH_ANY_PORT && dp_ports->src_port.upper < dp_ports->src_port.lower)
			return "Invalid tcp.src_port range";
		if (dp_ports->dst_port.lower != DP_FWALL_MATCH_ANY_PORT && dp_ports->dst_port.upper < dp_ports->dst_port.lower)
			return "Invalid tcp.dst_port range";
		break;
	case ProtocolFilter::kUdpFieldNumber:
		DPGRPC_LOG_INFO("Adding firewall rule filter",
						DP_LOG_FWRULE(grpc_rule.id().c_str()),
						DP_LOG_FWPROTO(IPPROTO_UDP),
						DP_LOG_FWSPORTFROM(grpc_filter.udp().src_port_lower()),
						DP_LOG_FWSPORTTO(grpc_filter.udp().src_port_upper()),
						DP_LOG_FWDPORTFROM(grpc_filter.udp().dst_port_lower()),
						DP_LOG_FWDPORTTO(grpc_filter.udp().dst_port_upper()));
		dp_rule->protocol = IPPROTO_UDP;
		if (!GrpcConv::GrpcToDpFwallPort(grpc_filter.udp().src_port_lower(), &dp_ports->src_port.lower))
			return "Invalid udp.src_port_lower";
		if (!GrpcConv::GrpcToDpFwallPort(grpc_filter.udp().dst_port_lower(), &dp_ports->dst_port.lower))
			return "Invalid udp.dst_port_lower";
		if (!GrpcConv::GrpcToDpFwallPort(grpc_filter.udp().src_port_upper(), &dp_ports->src_port.upper))
			return "Invalid udp.src_port_upper";
		if (!GrpcConv::GrpcToDpFwallPort(grpc_filter.udp().dst_port_upper(), &dp_ports->dst_port.upper))
			return "Invalid udp.dst_port_upper";
		if (dp_ports->src_port.lower != DP_FWALL_MATCH_ANY_PORT && dp_ports->src_port.upper < dp_ports->src_port.lower)
			return "Invalid udp.src_port range";
		if (dp_ports->dst_port.lower != DP_FWALL_MATCH_ANY_PORT && dp_ports->dst_port.upper < dp_ports->dst_port.lower)
			return "Invalid udp.dst_port range";
		break;
	case ProtocolFilter::kIcmpFieldNumber:
		DPGRPC_LOG_INFO("Adding firewall rule filter",
						DP_LOG_FWRULE(grpc_rule.id().c_str()),
						DP_LOG_FWPROTO(IPPROTO_ICMP),
						DP_LOG_FWICMPTYPE(grpc_filter.icmp().icmp_type()),
						DP_LOG_FWICMPCODE(grpc_filter.icmp().icmp_code()));
		dp_rule->protocol = IPPROTO_ICMP;
		dp_rule->filter.icmp.icmp_type = (uint32_t)grpc_filter.icmp().icmp_type();
		dp_rule->filter.icmp.icmp_code = (uint32_t)grpc_filter.icmp().icmp_code();
		if (dp_rule->filter.icmp.icmp_type != DP_FWALL_MATCH_ANY_ICMP_TYPE && dp_rule->filter.icmp.icmp_type > UINT8_MAX)
			return "Invalid icmp.icmp_type";
		if (dp_rule->filter.icmp.icmp_code != DP_FWALL_MATCH_ANY_ICMP_CODE && dp_rule->filter.icmp.icmp_code > UINT8_MAX)
			return "Invalid icmp.icmp_code";
		break;
	case ProtocolFilter::FILTER_NOT_SET:
	default:
		DPGRPC_LOG_INFO("Adding firewall rule filter",
						DP_LOG_FWRULE(grpc_rule.id().c_str()),
						DP_LOG_FWPROTO(DP_FWALL_MATCH_ANY_PROTOCOL));
		dp_rule->protocol = DP_FWALL_MATCH_ANY_PROTOCOL;
		dp_ports->src_port.lower = DP_FWALL_MATCH_ANY_PORT;
		dp_ports->dst_port.lower = DP_FWALL_MATCH_ANY_PORT;
	}
	return NULL;
}
void CreateFirewallRuleCall::ParseReply(struct dpgrpc_reply* reply)
{
	reply_.set_rule_id(&reply->fwrule.rule.rule_id, sizeof(reply->fwrule.rule.rule_id));
}

const char* DeleteFirewallRuleCall::FillRequest(struct dpgrpc_request* request)
{
	DPGRPC_LOG_INFO("Removing firewall rule",
					DP_LOG_IFACE(request_.interface_id().c_str()),
					DP_LOG_FWRULE(request_.rule_id().c_str()));
	if (SNPRINTF_FAILED(request->del_fwrule.iface_id, request_.interface_id()))
		return "Invalid interface_id";
	if (SNPRINTF_FAILED(request->del_fwrule.rule_id, request_.rule_id()))
		return "Invalid rule_id";
	return NULL;
}
void DeleteFirewallRuleCall::ParseReply(__rte_unused struct dpgrpc_reply* reply)
{
}

const char* GetFirewallRuleCall::FillRequest(struct dpgrpc_request* request)
{
	DPGRPC_LOG_INFO("Getting firewall rule info",
					DP_LOG_IFACE(request_.interface_id().c_str()),
					DP_LOG_FWRULE(request_.rule_id().c_str()));
	if (SNPRINTF_FAILED(request->get_fwrule.iface_id, request_.interface_id()))
		return "Invalid interface_id";
	if (SNPRINTF_FAILED(request->get_fwrule.rule_id, request_.rule_id()))
		return "Invalid rule_id";
	return NULL;
}
void GetFirewallRuleCall::ParseReply(struct dpgrpc_reply* reply)
{
	FirewallRule *rule = new FirewallRule();

	GrpcConv::DpToGrpcFwrule(&reply->fwrule.rule, rule);
	reply_.set_allocated_rule(rule);
}

const char* ListFirewallRulesCall::FillRequest(struct dpgrpc_request* request)
{
	DPGRPC_LOG_INFO("Listing firewall rules",
					DP_LOG_IFACE(request_.interface_id().c_str()));
	if (SNPRINTF_FAILED(request->list_fwrule.iface_id, request_.interface_id()))
		return "Invalid interface_id";
	return NULL;
}
void ListFirewallRulesCall::ParseReply(struct dpgrpc_reply* reply)
{
	struct dpgrpc_fwrule_info *grpc_rule;
	FirewallRule *rule;

	FOREACH_MESSAGE(grpc_rule, reply) {
		rule = reply_.add_rules();
		GrpcConv::DpToGrpcFwrule(&grpc_rule->rule, rule);
	}
}


const char* CheckVniInUseCall::FillRequest(struct dpgrpc_request* request)
{
	if (!GrpcConv::GrpcToDpVniType(request_.type(), &request->vni_in_use.type))
		return "Invalid type";
	request->vni_in_use.vni = request_.vni();
	DPGRPC_LOG_INFO("Checking VNI usage", DP_LOG_VNI(request->vni_in_use.vni),
					DP_LOG_VNI_TYPE(request->vni_in_use.type));
	return NULL;
}
void CheckVniInUseCall::ParseReply(struct dpgrpc_reply* reply)
{
	reply_.set_in_use(!!reply->vni_in_use.in_use);
}

const char* ResetVniCall::FillRequest(struct dpgrpc_request* request)
{
	if (!GrpcConv::GrpcToDpVniType(request_.type(), &request->vni_reset.type))
		return "Invalid type";
	request->vni_in_use.vni = request_.vni();
	DPGRPC_LOG_INFO("Resetting VNI", DP_LOG_VNI(request->vni_in_use.vni),
					DP_LOG_VNI_TYPE(request->vni_in_use.type));
	return NULL;
}
void ResetVniCall::ParseReply(__rte_unused struct dpgrpc_reply* reply)
{
}


const char* CaptureStartCall::FillRequest(struct dpgrpc_request* request)
{
	DPGRPC_LOG_INFO("Starting packet capture",
					DP_LOG_IPV6STR(request_.capture_config().sink_node_ip().address().c_str()),
					DP_LOG_L4PORT(request_.capture_config().udp_src_port()),
					DP_LOG_L4PORT(request_.capture_config().udp_dst_port()));

	if (request_.capture_config().udp_src_port() > UINT16_MAX)
		return "Invalid udp_src_port";
	if (request_.capture_config().udp_dst_port() > UINT16_MAX)
		return "Invalid udp_dst_port";
	if (!GrpcConv::StrToIpv6(request_.capture_config().sink_node_ip().address(), &request->capture_start.dst_addr6))
		return "Invalid sink_node_ip";

	request->capture_start.udp_src_port = (uint16_t)request_.capture_config().udp_src_port();
	request->capture_start.udp_dst_port = (uint16_t)request_.capture_config().udp_dst_port();

	if (request_.capture_config().interfaces_size() > DP_CAPTURE_MAX_PORT_NUM)
		return "Too many interfaces to be captured";

	request->capture_start.interface_count = 0;
	for (int i = 0; i < request_.capture_config().interfaces_size(); ++i) {
		if (!GrpcConv::GrpcToDpCaptureInterfaceType(request_.capture_config().interfaces(i).interface_type(), &request->capture_start.interfaces[i].type))
			return "Invalid interfaces.interface_type";

		switch (request->capture_start.interfaces[i].type) {
		case DP_CAPTURE_IFACE_TYPE_SINGLE_VF:
			DPGRPC_LOG_INFO("Setting packet capture on VF",
							DP_LOG_IFACE_TYPE(request_.capture_config().interfaces(i).interface_type()),
							DP_LOG_IFACE(request_.capture_config().interfaces(i).vf_name().c_str()));
			if (SNPRINTF_FAILED(request->capture_start.interfaces[i].spec.iface_id, request_.capture_config().interfaces(i).vf_name()))
				return "Invalid interface_id";
			break;
		case DP_CAPTURE_IFACE_TYPE_SINGLE_PF:
			DPGRPC_LOG_INFO("Setting packet capture on PF",
							DP_LOG_IFACE_TYPE(request_.capture_config().interfaces(i).interface_type()),
							DP_LOG_IFACE_INDEX(request_.capture_config().interfaces(i).pf_index()));
			if (request_.capture_config().interfaces(i).pf_index() > UINT8_MAX)
				return "Invalid pf_index";
			request->capture_start.interfaces[i].spec.pf_index = (uint8_t)request_.capture_config().interfaces(i).pf_index();
			break;
		}

		request->capture_start.interface_count++;
	}
	return NULL;
}
void CaptureStartCall::ParseReply(__rte_unused struct dpgrpc_reply* reply)
{
}

const char* CaptureStopCall::FillRequest(__rte_unused struct dpgrpc_request* request)
{
	DPGRPC_LOG_INFO("Stopping packet capture");
	return NULL;
}
void CaptureStopCall::ParseReply(struct dpgrpc_reply* reply)
{
	reply_.set_stopped_interface_cnt((uint32_t)reply->capture_stop.port_cnt);
}

const char* CaptureStatusCall::FillRequest(__rte_unused struct dpgrpc_request* request)
{
	DPGRPC_LOG_INFO("Getting packet capturing operation's status");
	return NULL;
}
void CaptureStatusCall::ParseReply(struct dpgrpc_reply* reply)
{
	const struct dpgrpc_capture	&capture_get = reply->capture_get;
	CaptureConfig *capture_config = new CaptureConfig();
	CapturedInterface *grpc_iface;
	char strbuf[INET6_ADDRSTRLEN];
	IpAddress *sink_ip;

	if (!capture_get.is_active) {
		reply_.set_is_active(false);
	} else {
		reply_.set_is_active(true);
		capture_config->set_udp_src_port(capture_get.udp_src_port);
		capture_config->set_udp_dst_port(capture_get.udp_dst_port);

		sink_ip = new IpAddress();
		DP_IPV6_TO_STR(&capture_get.dst_addr6, strbuf);
		sink_ip->set_address(strbuf);
		sink_ip->set_ipver(IpVersion::IPV6);
		capture_config->set_allocated_sink_node_ip(sink_ip);

		for (int i = 0; i < capture_get.interface_count; ++i) {
			grpc_iface = capture_config->add_interfaces();
			switch (capture_get.interfaces[i].type) {
				case DP_CAPTURE_IFACE_TYPE_SINGLE_PF:
					grpc_iface->set_interface_type(CaptureInterfaceType::SINGLE_PF);
					grpc_iface->set_pf_index(capture_get.interfaces[i].spec.pf_index);
					break;
				case DP_CAPTURE_IFACE_TYPE_SINGLE_VF:
					grpc_iface->set_interface_type(CaptureInterfaceType::SINGLE_VF);
					grpc_iface->set_vf_name(capture_get.interfaces[i].spec.iface_id);
					break;
			}
		}
		reply_.set_allocated_capture_config(capture_config);
	}
}
