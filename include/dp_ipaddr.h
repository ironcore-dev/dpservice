// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#ifndef __INCLUDE_DP_IPADDR_H__
#define __INCLUDE_DP_IPADDR_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <arpa/inet.h>
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include "dp_error.h"

#define DP_IPV6_ADDR_SIZE 16
static_assert(sizeof(uint64_t) * 2 == DP_IPV6_ADDR_SIZE, "DP_IPV6_ADDR_SIZE is invalid");

// TODO(plague): do something for naked ipv6, that uses uint8_t, thus cannot check size properly

// TODO(plague): move NAT64 handling here (part of the above) + grep for [12] which means NAT64 ipv6 -> ipv4 conversion and wrap it

// TODO(plague): This either needs to be a macro to enable checking for sizeof(addr) (or see above for the proposed ipv6 type)
static __rte_always_inline
bool dp_is_ipv6_addr_zero(const uint8_t *addr)
{
	return *((const uint64_t *)addr) == 0 && *((const uint64_t *)(addr + sizeof(uint64_t))) == 0;
}

static __rte_always_inline
bool dp_ipv6_match(const uint8_t *l, const uint8_t *r)
{
	return *((const uint64_t *)l) == *((const uint64_t *)r) && *((const uint64_t *)(l + sizeof(uint64_t))) == *((const uint64_t *)(r + sizeof(uint64_t)));
}

// structure for holding dual IP addresses
// made read-only without the right macro to prevent uninitialized bytes due to the the use of this structure in hash keys
struct dp_ip_address {
	union {
		uint8_t			_data[DP_IPV6_ADDR_SIZE];
		const uint8_t	ipv6[DP_IPV6_ADDR_SIZE];
		const uint32_t	ipv4;
	};
	union {
		bool			_is_v6;
		const bool		is_v6;
	};
} __rte_packed;

static inline void _dp_ipaddr_to_str_unsafe(const struct dp_ip_address *addr, char *dest)
{
	uint32_t net_ipv4;

	// inet_ntop() can only fail on invalid AF_ (constant here) and insufficient buffer size (checked in the macro)
	if (addr->is_v6) {
		inet_ntop(AF_INET6, &addr->ipv6, dest, INET6_ADDRSTRLEN);
	} else {
		net_ipv4 = htonl(addr->ipv4);
		inet_ntop(AF_INET, &net_ipv4, dest, INET_ADDRSTRLEN);
	}
}
#define DP_IPADDR_TO_STR(KEY, DST) do { \
	static_assert(sizeof(DST) >= INET6_ADDRSTRLEN, "Insufficient buffer size for DP_IPADDR_TO_STR()"); \
	_dp_ipaddr_to_str_unsafe((KEY), (DST)); \
} while (0)

static __rte_always_inline
void dp_copy_ipaddr(struct dp_ip_address *dst, const struct dp_ip_address *src)
{
	dst->_is_v6 = src->_is_v6;
	((uint64_t *)dst->_data)[0] = ((const uint64_t *)src->_data)[0];
	((uint64_t *)dst->_data)[1] = ((const uint64_t *)src->_data)[1];
}

// These cannot be inlines due to sizeof() being checked for IPv6
#define DP_SET_IPADDR6(ADDR, IPV6) do { \
	static_assert(sizeof(IPV6) == DP_IPV6_ADDR_SIZE, "Invalid IPv6 byte array passed to DP_FILL_IPADDR6()"); \
	DP_SET_IPADDR6_UNSAFE((ADDR), (IPV6)); \
} while (0)
#define DP_SET_IPADDR6_UNSAFE(ADDR, IPV6) do { \
	(ADDR)._is_v6 = true; \
	((uint64_t *)(ADDR)._data)[0] = ((const uint64_t *)(IPV6))[0]; \
	((uint64_t *)(ADDR)._data)[1] = ((const uint64_t *)(IPV6))[1]; \
} while (0)

#define DP_SET_IPADDR4(ADDR, IPV4) do { \
	(ADDR)._is_v6 = false; \
	((uint64_t *)(ADDR)._data)[0] = ((uint64_t *)(ADDR)._data)[1] = 0; \
	((uint32_t *)(ADDR)._data)[0] = (IPV4); \
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
