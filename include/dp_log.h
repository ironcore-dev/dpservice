// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#ifndef __INCLUDE_DP_LOG_H__
#define __INCLUDE_DP_LOG_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <rte_common.h>
#include <rte_log.h>

// Extend RTE's log types to enable filtering via --log-level=user*:#
#define RTE_LOGTYPE_DPSERVICE RTE_LOGTYPE_USER1
#define RTE_LOGTYPE_DPGRAPH   RTE_LOGTYPE_USER2
#define RTE_LOGTYPE_DPGRPC    RTE_LOGTYPE_USER3

// using canary values for format type should prevent at least some calling convetion bugs
#define _DP_LOG_FMT_CANARY_PRE  0x12300000
#define _DP_LOG_FMT_CANARY_POST 0x00000321
#define _DP_LOG_FMT_CREATE(VALUE) (_DP_LOG_FMT_CANARY_PRE | ((VALUE) << 12) | _DP_LOG_FMT_CANARY_POST)
#define _DP_LOG_FMT_STR _DP_LOG_FMT_CREATE(1)
#define _DP_LOG_FMT_INT _DP_LOG_FMT_CREATE(2)
#define _DP_LOG_FMT_UINT _DP_LOG_FMT_CREATE(3)
#define _DP_LOG_FMT_IPV4 _DP_LOG_FMT_CREATE(4)
#define _DP_LOG_FMT_PTR _DP_LOG_FMT_CREATE(5)
#define _DP_LOG_FMT_IPV6 _DP_LOG_FMT_CREATE(6)

// Do not call these directly unless absolutely necessary
// Create a wrapper macro to prevent typos and collisions in key names
#define _DP_LOG_STR(KEY, VALUE) KEY, _DP_LOG_FMT_STR, VALUE
#define _DP_LOG_INT(KEY, VALUE) KEY, _DP_LOG_FMT_INT, VALUE
#define _DP_LOG_UINT(KEY, VALUE) KEY, _DP_LOG_FMT_UINT, VALUE
#define _DP_LOG_IPV4(KEY, VALUE) KEY, _DP_LOG_FMT_IPV4, VALUE
#define _DP_LOG_IPV6(KEY, VALUE) KEY, _DP_LOG_FMT_IPV6, VALUE
#define _DP_LOG_PTR(KEY, VALUE) KEY, _DP_LOG_FMT_PTR, VALUE

// Macros to generate key-value pairs for structured logging
#define DP_LOG_RET(VALUE) _DP_LOG_INT("error", VALUE), _DP_LOG_STR("errmsg", dp_strerror(VALUE))
// used for types, values, limit checks, etc.
#define DP_LOG_VALUE(VALUE) _DP_LOG_INT("value", VALUE)
#define DP_LOG_MIN(VALUE) _DP_LOG_INT("min", VALUE)
#define DP_LOG_MAX(VALUE) _DP_LOG_INT("max", VALUE)
// used for tagged calls (like allocation pools, etc.)
#define DP_LOG_NAME(VALUE) _DP_LOG_STR("name", VALUE)
// RTE and NIC related
#define DP_LOG_PORTID(VALUE) _DP_LOG_UINT("port_id", VALUE)
#define DP_LOG_PEER_PORTID(VALUE) _DP_LOG_UINT("peer_port_id", VALUE)
#define DP_LOG_QUEUEID(VALUE) _DP_LOG_UINT("queue_id", VALUE)
#define DP_LOG_SOCKID(VALUE) _DP_LOG_INT("socket_id", VALUE)
#define DP_LOG_IFNAME(VALUE) _DP_LOG_STR("interface_name", VALUE)
#define DP_LOG_LCORE(VALUE) _DP_LOG_UINT("lcore_id", VALUE)
#define DP_LOG_RTE_GROUP(VALUE) _DP_LOG_UINT("rte_group", VALUE)
// networking stack
#define DP_LOG_IPV4(VALUE) _DP_LOG_IPV4("ipv4", VALUE)
#define DP_LOG_IPV6(VALUE) _DP_LOG_IPV6("ipv6", VALUE)
#define DP_LOG_SRC_IPV4(VALUE) _DP_LOG_IPV4("src_ipv4", VALUE)
#define DP_LOG_DST_IPV4(VALUE) _DP_LOG_IPV4("dst_ipv4", VALUE)
#define DP_LOG_L4PORT(VALUE) _DP_LOG_UINT("port", VALUE)
#define DP_LOG_SRC_PORT(VALUE) _DP_LOG_UINT("src_port", VALUE)
#define DP_LOG_DST_PORT(VALUE) _DP_LOG_UINT("dst_port", VALUE)
#define DP_LOG_PROTO(VALUE) _DP_LOG_UINT("protocol", VALUE)
// networking
#define DP_LOG_VNF_TYPE(VALUE) _DP_LOG_UINT("vnf_type", VALUE)
#define DP_LOG_VNI(VALUE) _DP_LOG_UINT("vni", VALUE)
#define DP_LOG_VNI_TYPE(VALUE) _DP_LOG_UINT("vni_type", VALUE)
#define DP_LOG_MINPORT(VALUE) _DP_LOG_UINT("minport", VALUE)
#define DP_LOG_MAXPORT(VALUE) _DP_LOG_UINT("maxport", VALUE)
#define DP_LOG_FLOW_ERROR(VALUE) _DP_LOG_STR("flow_error", VALUE)
// gRPC worker I/O
#define DP_LOG_GRPCRET(VALUE) _DP_LOG_INT("grpc_error", VALUE), _DP_LOG_STR("grpc_message", dp_grpc_strerror(VALUE))
#define DP_LOG_GRPCREQUEST(VALUE) _DP_LOG_INT("grpc_request", VALUE)
#define DP_LOG_IFACE(VALUE) _DP_LOG_STR("interface_id", VALUE)
#define DP_LOG_IFACE_INDEX(VALUE) _DP_LOG_INT("interface_index", VALUE)
#define DP_LOG_IFACE_TYPE(VALUE) _DP_LOG_UINT("interface_type", VALUE)
#define DP_LOG_TVNI(VALUE) _DP_LOG_UINT("t_vni", VALUE)
#define DP_LOG_PCI(VALUE) _DP_LOG_STR("pci", VALUE)
#define DP_LOG_PXE_SRV(VALUE) _DP_LOG_STR("pxe_server", VALUE)
#define DP_LOG_PXE_PATH(VALUE) _DP_LOG_STR("pxe_path", VALUE)
#define DP_LOG_IPV4STR(VALUE) _DP_LOG_STR("ipv4", VALUE)
#define DP_LOG_IPV6STR(VALUE) _DP_LOG_STR("ipv6", VALUE)
#define DP_LOG_LBID(VALUE) _DP_LOG_STR("lb_id", VALUE)
#define DP_LOG_PREFIX(VALUE) _DP_LOG_STR("prefix", VALUE)
#define DP_LOG_PREFLEN(VALUE) _DP_LOG_UINT("prefix_len", VALUE)
#define DP_LOG_FWRULE(VALUE) _DP_LOG_STR("fw_rule", VALUE)
#define DP_LOG_FWPRIO(VALUE) _DP_LOG_UINT("fw_priority", VALUE)
#define DP_LOG_FWDIR(VALUE) _DP_LOG_UINT("fw_direction", VALUE)
#define DP_LOG_FWACTION(VALUE) _DP_LOG_UINT("fw_action", VALUE)
#define DP_LOG_FWSRC(VALUE) _DP_LOG_STR("fw_src", VALUE)
#define DP_LOG_FWSRCLEN(VALUE) _DP_LOG_UINT("fw_srclen", VALUE)
#define DP_LOG_FWDST(VALUE) _DP_LOG_STR("fw_dst", VALUE)
#define DP_LOG_FWDSTLEN(VALUE) _DP_LOG_UINT("fw_dstlen", VALUE)
#define DP_LOG_FWPROTO(VALUE) _DP_LOG_UINT("fw_proto", VALUE)
#define DP_LOG_FWSPORTFROM(VALUE) _DP_LOG_INT("fw_sport_from", VALUE)
#define DP_LOG_FWSPORTTO(VALUE) _DP_LOG_INT("fw_sport_to", VALUE)
#define DP_LOG_FWDPORTFROM(VALUE) _DP_LOG_INT("fw_dport_from", VALUE)
#define DP_LOG_FWDPORTTO(VALUE) _DP_LOG_INT("fw_dport_to", VALUE)
#define DP_LOG_FWICMPTYPE(VALUE) _DP_LOG_UINT("fw_icmp_type", VALUE)
#define DP_LOG_FWICMPCODE(VALUE) _DP_LOG_UINT("fw_icmp_code", VALUE)
#define DP_LOG_PROTOVER(VALUE) _DP_LOG_STR("proto_ver", VALUE)
#define DP_LOG_CLIENTNAME(VALUE) _DP_LOG_STR("client_name", VALUE)
#define DP_LOG_CLIENTVER(VALUE) _DP_LOG_STR("client_ver", VALUE)
// module-specific
#define DP_LOG_NODE(VALUE) _DP_LOG_STR("node", (VALUE)->name)
#define DP_LOG_TELEMETRY_CMD(VALUE) _DP_LOG_STR("telemetry_cmd", VALUE)
#define DP_LOG_NETLINK(VALUE) _DP_LOG_STR("netlink_msg", VALUE)
// compound macros
#define DP_LOG_PORT(VALUE) DP_LOG_PORTID((VALUE)->port_id), DP_LOG_SOCKID((VALUE)->socket_id)


#define DP_STRUCTURED_LOG(LEVEL, LOGTYPE, MESSAGE, ...) \
	_dp_log(RTE_LOG_##LEVEL, RTE_LOGTYPE_DP##LOGTYPE, \
			__FILE__, __LINE__, __FUNCTION__, \
			MESSAGE, ##__VA_ARGS__, NULL)

// this way IDE autocomplete and click-through is working while not needing to write the full level/logtype names
#define DPS_LOG_ERR(MESSAGE, ...)     DP_STRUCTURED_LOG(ERR,     SERVICE, MESSAGE, ##__VA_ARGS__)
#define DPS_LOG_WARNING(MESSAGE, ...) DP_STRUCTURED_LOG(WARNING, SERVICE, MESSAGE, ##__VA_ARGS__)
#define DPS_LOG_INFO(MESSAGE, ...)    DP_STRUCTURED_LOG(INFO,    SERVICE, MESSAGE, ##__VA_ARGS__)
#define DPS_LOG_DEBUG(MESSAGE, ...)   DP_STRUCTURED_LOG(DEBUG,   SERVICE, MESSAGE, ##__VA_ARGS__)

#define DPGRPC_LOG_ERR(MESSAGE, ...)     DP_STRUCTURED_LOG(ERR,     GRPC, MESSAGE, ##__VA_ARGS__)
#define DPGRPC_LOG_WARNING(MESSAGE, ...) DP_STRUCTURED_LOG(WARNING, GRPC, MESSAGE, ##__VA_ARGS__)
#define DPGRPC_LOG_INFO(MESSAGE, ...)    DP_STRUCTURED_LOG(INFO,    GRPC, MESSAGE, ##__VA_ARGS__)
#define DPGRPC_LOG_DEBUG(MESSAGE, ...)   DP_STRUCTURED_LOG(DEBUG,   GRPC, MESSAGE, ##__VA_ARGS__)

#define DPNODE_LOG_ERR(NODE, MESSAGE, ...)     DP_STRUCTURED_LOG(ERR,     GRAPH, MESSAGE, DP_LOG_NODE(NODE), ##__VA_ARGS__)
#define DPNODE_LOG_WARNING(NODE, MESSAGE, ...) DP_STRUCTURED_LOG(WARNING, GRAPH, MESSAGE, DP_LOG_NODE(NODE), ##__VA_ARGS__)
#define DPNODE_LOG_INFO(NODE, MESSAGE, ...)    DP_STRUCTURED_LOG(INFO,    GRAPH, MESSAGE, DP_LOG_NODE(NODE), ##__VA_ARGS__)
#define DPNODE_LOG_DEBUG(NODE, MESSAGE, ...)   DP_STRUCTURED_LOG(DEBUG,   GRAPH, MESSAGE, DP_LOG_NODE(NODE), ##__VA_ARGS__)

void dp_log_set_thread_name(const char *name);

int dp_log_init(void);

__rte_cold
void _dp_log(unsigned int level, unsigned int logtype,
			 const char *file, unsigned int line, const char *function,
			 const char *message, ...);

/** Use this for logging before dp_log_init() */
__rte_cold __rte_format_printf(2, 3)
void _dp_log_early(FILE *f, const char *format, ...);

#define DP_EARLY_ERR(FORMAT, ...) _dp_log_early(stderr, FORMAT, ##__VA_ARGS__)

#ifdef __cplusplus
}
#endif
#endif
