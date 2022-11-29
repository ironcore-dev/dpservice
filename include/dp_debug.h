#ifndef _DP_DEBUG_H_
#define _DP_DEBUG_H_

#include "dp_util.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef ENABLE_GRAPHTRACE
// TODO printf -> macro
#	define GRAPHTRACE_BURST(NODE, BURST, COUNT) do { \
		if (dp_get_graphtrace_level() < 2) \
			break; \
		for (uint _graphtrace_i = 0; _graphtrace_i < (COUNT); ++_graphtrace_i) { \
			struct rte_mbuf *_graphtrace_pkt = (BURST)[_graphtrace_i]; \
			printf("%-11s #%u: %p\n", (NODE)->name, _graphtrace_i, _graphtrace_pkt); \
		} \
	} while (0)
#	define GRAPHTRACE_BURST_NEXT(NODE, BURST, COUNT, NEXT) do { \
		if (dp_get_graphtrace_level() < 1) \
			break; \
		for (uint _graphtrace_i = 0; _graphtrace_i < (COUNT); ++_graphtrace_i) { \
			struct rte_mbuf *_graphtrace_pkt = (BURST)[_graphtrace_i]; \
			printf("%-11s #%u: %p -> %s\n", (NODE)->name, _graphtrace_i, _graphtrace_pkt, (NODE)->nodes[NEXT]->name); \
		} \
	} while (0)
#	define GRAPHTRACE_BURST_TX(NODE, BURST, COUNT, PORT) do { \
		if (dp_get_graphtrace_level() < 1) \
			break; \
		for (uint _graphtrace_i = 0; _graphtrace_i < (COUNT); ++_graphtrace_i) { \
			struct rte_mbuf *_graphtrace_pkt = (BURST)[_graphtrace_i]; \
			printf("%-11s #%u: %p >> PORT %d\n", (NODE)->name, _graphtrace_i, _graphtrace_pkt, (PORT)); \
		} \
	} while (0)
#	define GRAPHTRACE_PKT(NODE, PKT) do { \
		if (dp_get_graphtrace_level() < 2) \
			break; \
		printf("%-14s: %p\n", (NODE)->name, (PKT)); \
	} while (0)
#	define GRAPHTRACE_PKT_NEXT(NODE, PKT, NEXT) do { \
		if (dp_get_graphtrace_level() < 1) \
			break; \
		printf("%-14s: %p -> %s\n", (NODE)->name, (PKT), (NODE)->nodes[NEXT]->name); \
	} while (0)
#	define GRAPHTRACE_PKT_TX(NODE, PKT, PORT) do { \
		if (dp_get_graphtrace_level() < 1) \
			break; \
		printf("%-14s: %p >> PORT %d\n", (NODE)->name, (PKT), (PORT)); \
	} while (0)
#else
#	define GRAPHTRACE_BURST(NODE, BURST, COUNT)
#	define GRAPHTRACE_BURST_NEXT(NODE, BURST, COUNT, NEXT)
#	define GRAPHTRACE_BURST_TX(NODE, BURST, COUNT, PORT)
#	define GRAPHTRACE_PKT(NODE, PKT)
#	define GRAPHTRACE_PKT_NEXT(NODE, PKT, NEXT)
#	define GRAPHTRACE_PKT_TX(NODE, PKT, PORT)
#endif

#ifdef __cplusplus
}
#endif

#endif
