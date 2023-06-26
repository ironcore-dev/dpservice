#ifndef __INCLUDE_DP_LOG_H__
#define __INCLUDE_DP_LOG_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <rte_common.h>
#include <rte_log.h>

#define RTE_LOGTYPE_DPSERVICE RTE_LOGTYPE_USER1
#define RTE_LOGTYPE_DPGRAPH   RTE_LOGTYPE_USER2
#define RTE_LOGTYPE_DPGRPC    RTE_LOGTYPE_USER3

//
// ----- Macros to generate key-value pairs for structured logging
//

// using canary values for format type should prevent at least some calling convetion bugs
#define _DP_LOG_FMT_CANARY_PRE  0x12300000
#define _DP_LOG_FMT_CANARY_POST 0x00000321
#define _DP_LOG_FMT_CREATE(VALUE) (_DP_LOG_FMT_CANARY_PRE | ((VALUE) << 12) | _DP_LOG_FMT_CANARY_POST)
#define _DP_LOG_FMT_STR _DP_LOG_FMT_CREATE(1)
#define _DP_LOG_FMT_INT _DP_LOG_FMT_CREATE(2)
#define _DP_LOG_FMT_UINT _DP_LOG_FMT_CREATE(3)
#define _DP_LOG_FMT_IPV4 _DP_LOG_FMT_CREATE(4)
#define _DP_LOG_FMT_IPV6 _DP_LOG_FMT_CREATE(6)

// Do not call these directly unless absolutely necessary
// Create a wrapper macro to prevent typos and collisions in key names
#define _DP_LOG_STR(KEY, VALUE) KEY, _DP_LOG_FMT_STR, VALUE
#define _DP_LOG_INT(KEY, VALUE) KEY, _DP_LOG_FMT_INT, VALUE
#define _DP_LOG_UINT(KEY, VALUE) KEY, _DP_LOG_FMT_UINT, VALUE
#define _DP_LOG_IPV4(KEY, VALUE) KEY, _DP_LOG_FMT_IPV4, VALUE
#define _DP_LOG_IPV6(KEY, VALUE) KEY, _DP_LOG_FMT_IPV6, VALUE

#define DP_LOG_RET(VALUE) _DP_LOG_INT("error", VALUE), _DP_LOG_STR("errmsg", dp_strerror_structured(VALUE))

#define DP_LOG_GRPCRET(VALUE) _DP_LOG_INT("grpc_error", VALUE), _DP_LOG_STR("grpc_message", dp_grpc_strerror(VALUE))
#define DP_LOG_GRPCREQUEST(VALUE) _DP_LOG_INT("grpc_request", VALUE)

#define DP_LOG_LISTENADDR(VALUE) _DP_LOG_STR("listen_address", VALUE)

#define DP_LOG_IFACE(VALUE) _DP_LOG_STR("interface_id", VALUE)
#define DP_LOG_VNI(VALUE) _DP_LOG_UINT("vni", VALUE)
#define DP_LOG_VNI_TYPE(VALUE) _DP_LOG_UINT("vni_type", VALUE)
#define DP_LOG_TVNI(VALUE) _DP_LOG_UINT("t_vni", VALUE)
#define DP_LOG_IPV4STR(VALUE) _DP_LOG_STR("ipv4", VALUE)
#define DP_LOG_IPV6STR(VALUE) _DP_LOG_STR("ipv6", VALUE)
#define DP_LOG_PCI(VALUE) _DP_LOG_STR("pci", VALUE)
#define DP_LOG_PXE_SRV(VALUE) _DP_LOG_STR("pxe_server", VALUE)
#define DP_LOG_PXE_PATH(VALUE) _DP_LOG_STR("pxe_path", VALUE)
#define DP_LOG_LBID(VALUE) _DP_LOG_STR("lb_id", VALUE)
#define DP_LOG_PORT(VALUE) _DP_LOG_UINT("port", VALUE)
#define DP_LOG_PROTO(VALUE) _DP_LOG_UINT("protocol", VALUE)
#define DP_LOG_PREFIX(VALUE) _DP_LOG_STR("prefix", VALUE)
#define DP_LOG_PREFLEN(VALUE) _DP_LOG_UINT("prefix_len", VALUE)
#define DP_LOG_MINPORT(VALUE) _DP_LOG_UINT("min_port", VALUE)
#define DP_LOG_MAXPORT(VALUE) _DP_LOG_UINT("max_port", VALUE)
#define DP_LOG_NATINFOTYPE(VALUE) _DP_LOG_UINT("nat_info_type", VALUE)

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

//
// -----
//

// TODO(plague): This is now a mess because of transitional state of logging
// over time, this will get converted

__rte_cold
#ifdef DEBUG
__rte_format_printf(6, 7)
#else
__rte_format_printf(3, 4)
#endif
void _dp_log(unsigned int level, unsigned int logtype,
#ifdef DEBUG
			 const char *file, unsigned int line, const char *function,
#endif
			 const char *format, ...);

__rte_cold void _dp_log_structured(unsigned int level, unsigned int logtype,
#ifdef DEBUG
								   const char *file, unsigned int line, const char *function,
#endif
								   const char *message, ...);

// TODO is this still intented to be debuglevel only? Maybe on release only function name?
#ifdef DEBUG
#	define _DP_LOG_DEBUGINFO __FILE__, __LINE__, __FUNCTION__,
#else
#	define _DP_LOG_DEBUGINFO
#endif
#define DP_LOG(LEVEL, LOGTYPE, FORMAT, ...) \
	_dp_log(RTE_LOG_##LEVEL, RTE_LOGTYPE_DP##LOGTYPE, \
			_DP_LOG_DEBUGINFO \
			FORMAT, ##__VA_ARGS__)

#define DP_LOG_STRUCTURED(LEVEL, LOGTYPE, MESSAGE, ...) \
	_dp_log_structured(RTE_LOG_##LEVEL, RTE_LOGTYPE_DP##LOGTYPE, \
					   _DP_LOG_DEBUGINFO \
					   MESSAGE, ##__VA_ARGS__, NULL)

// this way IDE autocomplete and click-through is working while not needing to write the full level/logtype names
#define DPS_LOG_ERR(FORMAT, ...)     DP_LOG(ERR,     SERVICE, FORMAT, ##__VA_ARGS__)
#define DPS_LOG_WARNING(FORMAT, ...) DP_LOG(WARNING, SERVICE, FORMAT, ##__VA_ARGS__)
#define DPS_LOG_INFO(FORMAT, ...)    DP_LOG(INFO,    SERVICE, FORMAT, ##__VA_ARGS__)
#define DPS_LOG_DEBUG(FORMAT, ...)   DP_LOG(DEBUG,   SERVICE, FORMAT, ##__VA_ARGS__)

#define DPGRPC_LOG_ERR(MESSAGE, ...)     DP_LOG_STRUCTURED(ERR,     GRPC, MESSAGE, ##__VA_ARGS__)
#define DPGRPC_LOG_WARNING(MESSAGE, ...) DP_LOG_STRUCTURED(WARNING, GRPC, MESSAGE, ##__VA_ARGS__)
#define DPGRPC_LOG_INFO(MESSAGE, ...)    DP_LOG_STRUCTURED(INFO,    GRPC, MESSAGE, ##__VA_ARGS__)
#define DPGRPC_LOG_DEBUG(MESSAGE, ...)   DP_LOG_STRUCTURED(DEBUG,   GRPC, MESSAGE, ##__VA_ARGS__)

#define DPNODE_LOG_ERR(NODE, FORMAT, ...)     DP_LOG(ERR,     GRAPH, "%s: " FORMAT, (NODE)->name, ##__VA_ARGS__)
#define DPNODE_LOG_WARNING(NODE, FORMAT, ...) DP_LOG(WARNING, GRAPH, "%s: " FORMAT, (NODE)->name, ##__VA_ARGS__)
#define DPNODE_LOG_INFO(NODE, FORMAT, ...)    DP_LOG(INFO,    GRAPH, "%s: " FORMAT, (NODE)->name, ##__VA_ARGS__)
#define DPNODE_LOG_DEBUG(NODE, FORMAT, ...)   DP_LOG(DEBUG,   GRAPH, "%s: " FORMAT, (NODE)->name, ##__VA_ARGS__)

void dp_log_set_thread_name(const char *name);

int dp_log_init();

/** Use this for logging before dp_log_init() */
__rte_cold __rte_format_printf(2, 3)
void _dp_log_early(FILE *f, const char *format, ...);

#define DP_EARLY_ERR(FORMAT, ...) _dp_log_early(stderr, FORMAT, ##__VA_ARGS__)

#ifdef __cplusplus
}
#endif
#endif
