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

#define _DP_LOG_TYPE_SERVICE "SERVICE"
#define _DP_LOG_TYPE_GRAPH   "GRAPH"
#define _DP_LOG_TYPE_GRPC    "GRPC"

// some of these are intentionally commented-out to prevent usage
// (static_assert cannot be used here due to token pasting below)
// #define _DP_LOG_LEVEL_EMERG   "M"
// #define _DP_LOG_LEVEL_ALERT   "A"
// #define _DP_LOG_LEVEL_CRIT    "C"
#define _DP_LOG_LEVEL_ERR     "E"
#define _DP_LOG_LEVEL_WARNING "W"
// #define _DP_LOG_LEVEL_NOTICE  "N"
#define _DP_LOG_LEVEL_INFO    "I"
#define _DP_LOG_LEVEL_DEBUG   "D"


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

#ifdef DEBUG
#	define _DP_LOG_DEBUGINFO __FILE__, __LINE__, __FUNCTION__,
#else
#	define _DP_LOG_DEBUGINFO
#endif
#define DP_LOG(LEVEL, LOGTYPE, FORMAT, ...) \
	_dp_log(RTE_LOG_##LEVEL, RTE_LOGTYPE_DP##LOGTYPE, \
			_DP_LOG_DEBUGINFO \
			_DP_LOG_LEVEL_##LEVEL " " _DP_LOG_TYPE_##LOGTYPE ": " FORMAT, \
			##__VA_ARGS__)

// printf-like macros for easier wrapping in macros later
// also this way IDE autocomplete and click-through is working
#define DPS_LOG_ERR(FORMAT, ...)     DP_LOG(ERR,     SERVICE, FORMAT, ##__VA_ARGS__)
#define DPS_LOG_WARNING(FORMAT, ...) DP_LOG(WARNING, SERVICE, FORMAT, ##__VA_ARGS__)
#define DPS_LOG_INFO(FORMAT, ...)    DP_LOG(INFO,    SERVICE, FORMAT, ##__VA_ARGS__)
#define DPS_LOG_DEBUG(FORMAT, ...)   DP_LOG(DEBUG,   SERVICE, FORMAT, ##__VA_ARGS__)

#define DPGRPC_LOG_ERR(FORMAT, ...)     DP_LOG(ERR,     GRPC, FORMAT, ##__VA_ARGS__)
#define DPGRPC_LOG_WARNING(FORMAT, ...) DP_LOG(WARNING, GRPC, FORMAT, ##__VA_ARGS__)
#define DPGRPC_LOG_INFO(FORMAT, ...)    DP_LOG(INFO,    GRPC, FORMAT, ##__VA_ARGS__)
#define DPGRPC_LOG_DEBUG(FORMAT, ...)   DP_LOG(DEBUG,   GRPC, FORMAT, ##__VA_ARGS__)

#define DPNODE_LOG_ERR(NODE, FORMAT, ...)     DP_LOG(ERR,     GRAPH, "%s: " FORMAT, (NODE)->name, ##__VA_ARGS__)
#define DPNODE_LOG_WARNING(NODE, FORMAT, ...) DP_LOG(WARNING, GRAPH, "%s: " FORMAT, (NODE)->name, ##__VA_ARGS__)
#define DPNODE_LOG_INFO(NODE, FORMAT, ...)    DP_LOG(INFO,    GRAPH, "%s: " FORMAT, (NODE)->name, ##__VA_ARGS__)
#define DPNODE_LOG_DEBUG(NODE, FORMAT, ...)   DP_LOG(DEBUG,   GRAPH, "%s: " FORMAT, (NODE)->name, ##__VA_ARGS__)

void dp_log_set_thread_name(const char *name);

#ifdef __cplusplus
}
#endif

#endif
