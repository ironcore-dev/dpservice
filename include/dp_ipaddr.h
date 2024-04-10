// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#ifndef __INCLUDE_DP_IPADDR_H__
#define __INCLUDE_DP_IPADDR_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <assert.h>
#include <stdint.h>
#include <stdbool.h>

#define DP_IPV6_ADDR_SIZE 16

struct dp_ip_address {
	bool			is_v6;
	union {
		// TODO maybe define this so there is no code duplication
		uint32_t	_data[4];
		// TODO should this be visible or not?
		uint8_t		ipv6[DP_IPV6_ADDR_SIZE];
		uint32_t	ipv4;
	};
};

// To be used for hash keys needing dp_ip_address
static_assert(sizeof(uint32_t)*4 == DP_IPV6_ADDR_SIZE, "DP_IPV6_ADDR_SIZE is invalid");
struct dp_ip_addr_key {
	uint32_t	_data[4];
	// TODO also hide using underscore?
	bool		is_v6;
} __rte_packed;

static __rte_always_inline
void dp_fill_ipaddr(struct dp_ip_address *dst_addr, const struct dp_ip_addr_key *src_key)
{
	dst_addr->is_v6 = src_key->is_v6;
	dst_addr->_data[0] = src_key->_data[0];
	dst_addr->_data[1] = src_key->_data[1];
	dst_addr->_data[2] = src_key->_data[2];
	dst_addr->_data[3] = src_key->_data[3];
}

static __rte_always_inline
void dp_fill_ipkey(struct dp_ip_addr_key *dst_key, const struct dp_ip_address *src_addr)
{
	dst_key->is_v6 = src_addr->is_v6;
	dst_key->_data[0] = src_addr->_data[0];
	dst_key->_data[1] = src_addr->_data[1];
	dst_key->_data[2] = src_addr->_data[2];
	dst_key->_data[3] = src_addr->_data[3];
}
// TODO macro/inline to copy the array

// These cannot be inlines due to sizeof() being checked here
#define DP_FILL_IPKEY6(KEY, IPV6) do { \
	static_assert(sizeof(IPV6) == DP_IPV6_ADDR_SIZE, "Invalid IPv6 byte array passed to DP_FILL_IPKEY6()"); \
	(KEY).is_v6 = true; \
	(KEY)._data[0] = ((const uint32_t *)(IPV6))[0]; \
	(KEY)._data[1] = ((const uint32_t *)(IPV6))[1]; \
	(KEY)._data[2] = ((const uint32_t *)(IPV6))[2]; \
	(KEY)._data[3] = ((const uint32_t *)(IPV6))[3]; \
} while (0)

#define DP_FILL_IPKEY4(KEY, IPV4) do { \
	(KEY).is_v6 = false; \
	(KEY)._data[0] = (IPV4); \
	(KEY)._data[1] = (KEY)._data[2] = (KEY)._data[3] = 0; \
} while (0)


// inspired by DPDK's RTE_ETHER_ADDR_PRT_FMT and RTE_ETHER_ADDR_BYTES
// network byte-order!
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
