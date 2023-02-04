#ifndef __INCLUDE_DP_UTIL_H__
#define __INCLUDE_DP_UTIL_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include <net/if.h>
#include <rte_byteorder.h>
#include <rte_ethdev.h>
#include <rte_hash.h>
#include <rte_log.h>
#include <rte_mbuf.h>

#include "dp_conf.h"

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

int dp_get_dev_info(uint16_t port_id, struct rte_eth_dev_info *dev_info, char ifname[IFNAMSIZ]);

int dp_get_num_of_vfs();

void rewrite_eth_hdr(struct rte_mbuf *m, uint16_t port_id, uint16_t eth_type);

void dp_fill_ipv4_print_buff(unsigned int ip, char *buf);


struct rte_hash *dp_create_jhash_table(int entries, size_t key_len, const char *name, int socket_id);


// inspired by DPDK's RTE_ETHER_ADDR_PRT_FMT and RTE_ETHER_ADDR_BYTES
// TODO(plague): apply this to dp_fill_ipv4_print_buff()
#define DP_IPV4_PRINT_FMT       "%u.%u.%u.%u"
#define DP_IPV4_PRINT_BYTES(ip) (ip) & 0xFF, \
								((ip) >> 8) & 0xFF, \
								((ip) >> 16) & 0xFF, \
								((ip) >> 24) & 0xFF

#define DP_IPV6_PRINT_FMT       "%x:%x:%x:%x:%x:%x:%x:%x"
#define DP_IPV6_PRINT_BYTES(ip) rte_cpu_to_be_16(((uint16_t *)(ip))[0]), \
								rte_cpu_to_be_16(((uint16_t *)(ip))[1]), \
								rte_cpu_to_be_16(((uint16_t *)(ip))[2]), \
								rte_cpu_to_be_16(((uint16_t *)(ip))[3]), \
								rte_cpu_to_be_16(((uint16_t *)(ip))[4]), \
								rte_cpu_to_be_16(((uint16_t *)(ip))[5]), \
								rte_cpu_to_be_16(((uint16_t *)(ip))[6]), \
								rte_cpu_to_be_16(((uint16_t *)(ip))[7])

#ifdef __cplusplus
}
#endif
#endif
