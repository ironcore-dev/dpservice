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
static_assert(sizeof(uint32_t)*4 == DP_IPV6_ADDR_SIZE, "DP_IPV6_ADDR_SIZE is invalid");

struct dp_ip_address {
	union {
		uint32_t		_data[DP_IPV6_ADDR_SIZE/sizeof(uint32_t)];
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
	dst->_data[0] = src->_data[0];
	dst->_data[1] = src->_data[1];
	dst->_data[2] = src->_data[2];
	dst->_data[3] = src->_data[3];
}
// TODO macro/inline to copy the array??
// TODO actually a helpful macro to copy IPv6 and guard the sizeof!

// TODO move the is_addr_zero here

// These cannot be inlines due to sizeof() being checked for IPv6
#define DP_SET_IPADDR6(ADDR, IPV6) do { \
	static_assert(sizeof(IPV6) == DP_IPV6_ADDR_SIZE, "Invalid IPv6 byte array passed to DP_FILL_IPADDR6()"); \
	DP_SET_IPADDR6_UNSAFE((ADDR), (IPV6)); \
} while (0)
#define DP_SET_IPADDR6_UNSAFE(ADDR, IPV6) do { \
	(ADDR)._is_v6 = true; \
	(ADDR)._data[0] = ((const uint32_t *)(IPV6))[0]; \
	(ADDR)._data[1] = ((const uint32_t *)(IPV6))[1]; \
	(ADDR)._data[2] = ((const uint32_t *)(IPV6))[2]; \
	(ADDR)._data[3] = ((const uint32_t *)(IPV6))[3]; \
} while (0)

#define DP_SET_IPADDR4(ADDR, IPV4) do { \
	(ADDR)._is_v6 = false; \
	(ADDR)._data[0] = (IPV4); \
	(ADDR)._data[1] = (ADDR)._data[2] = (ADDR)._data[3] = 0; \
} while (0)

// TODO move NAT64 here?


// TODO these should be obsolete by now (logging already provides this)
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
