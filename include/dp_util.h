#ifndef __INCLUDE_DP_UTIL_H__
#define __INCLUDE_DP_UTIL_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include <rte_log.h>
#include <rte_mbuf.h>

#include "dp_conf.h"

#define DP_TIMESTAMP_BUF_SIZE 26

#define RTE_LOGTYPE_DPSERVICE RTE_LOGTYPE_USER1
#define RTE_LOGTYPE_GRAPHTRACE RTE_LOGTYPE_USER2
// TODO(plague) this uses local definition but does not hide them properly
// DPS_LOG(X, Y, "%s", buf); will lead to a bug!
// TODO(plague) --log-level=1 will cause this to print only time!
#define DPS_LOG(l, t, ...)						\
	do {										\
	char buf[DP_TIMESTAMP_BUF_SIZE] = {0};		\
	if ((uint32_t)rte_log_get_level(RTE_LOGTYPE_ ## t) >= RTE_LOG_ ## l) {\
	time_t now = time(NULL);					\
	strftime(buf, DP_TIMESTAMP_BUF_SIZE - 1, "%Y-%m-%d %H:%M:%S", gmtime(&now));\
	fprintf(rte_log_get_stream(), "%s ", buf);	\
	rte_log(RTE_LOG_ ## l,						\
		 RTE_LOGTYPE_ ## t, # t ": " __VA_ARGS__);\
	};											\
	} while (0)

#define VM_MACHINE_ID_STR_LEN	64
#define VM_MACHINE_PXE_STR_LEN	32
#define DP_LB_ID_SIZE			64
#define DP_LB_PORT_SIZE			16

#define DP_MAC_EQUAL(mac1, mac2) (((mac1)->addr_bytes[0] == (mac2)->addr_bytes[0]) && \
								((mac1)->addr_bytes[1] == (mac2)->addr_bytes[1]) && \
								((mac1)->addr_bytes[2] == (mac2)->addr_bytes[2]) && \
								((mac1)->addr_bytes[3] == (mac2)->addr_bytes[3]) && \
								((mac1)->addr_bytes[4] == (mac2)->addr_bytes[4]) && \
								((mac1)->addr_bytes[5] == (mac2)->addr_bytes[5]))

static inline bool dp_is_mellanox_opt_set()
{
	return dp_conf_get_eal_a_pf0()[0] != '\0'
		&& dp_conf_get_eal_a_pf1()[0] != '\0';
}

uint16_t dp_get_pf1_port_id();
uint16_t dp_get_pf0_port_id();
bool dp_is_pf_port_id(uint16_t id);
void dp_add_pf_port_id(uint16_t id);
int dp_get_num_of_vfs();

void rewrite_eth_hdr(struct rte_mbuf *m, uint16_t port_id, uint16_t eth_type);

void print_ip(unsigned int ip, char *buf);

#ifdef __cplusplus
}
#endif
#endif
