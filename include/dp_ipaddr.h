// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#ifndef __INCLUDE_DP_IPADDR_H__
#define __INCLUDE_DP_IPADDR_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdbool.h>
#include <rte_ip.h>
#include "dp_error.h"

#define DP_IPV6_ADDR_SIZE 16
static_assert(sizeof(rte_be64_t) * 2 == DP_IPV6_ADDR_SIZE, "DP_IPV6_ADDR_SIZE is invalid");

// structure for holding IPv6 addresses
// this way sizeof(dp_ipv6 *) is a meaningful value and passing the pointer only is safe
union dp_ipv6 {
	struct {
		rte_be64_t	_prefix;
		rte_be64_t	_suffix;
	};
	const uint8_t	bytes[DP_IPV6_ADDR_SIZE];
};
static_assert(sizeof(union dp_ipv6) == DP_IPV6_ADDR_SIZE, "union dp_ipv6 has padding");

static __rte_always_inline
void dp_copy_ipv6(union dp_ipv6 *dst, const union dp_ipv6 *src)
{
	dst->_prefix = src->_prefix;
	dst->_suffix = src->_suffix;
}

// TODO reduce use of these as much as possible (re-check at the end
#define DP_IPV6_FROM_ARRAY(IPV6, ARRAY) do { \
	static_assert(sizeof(ARRAY) == sizeof(union dp_ipv6), "Invalid array size for DP_SET_IPV6"); \
	dp_copy_ipv6((IPV6), (const union dp_ipv6 *)(ARRAY)); \
} while (0)

#define DP_ARRAY_FROM_IPV6(ARRAY, IPV6) do { \
	static_assert(sizeof(ARRAY) == sizeof(union dp_ipv6), "Invalid array size for DP_IPV6_TO_ARRAY"); \
	dp_copy_ipv6((union dp_ipv6 *)(ARRAY), (IPV6)); \
} while (0)

static __rte_always_inline
const union dp_ipv6 *dp_get_src_ipv6(const struct rte_ipv6_hdr *ipv6_hdr)
{
	static_assert(sizeof(ipv6_hdr->src_addr) == sizeof(union dp_ipv6), "Structure dp_ipv6 is not compatible with IPv6 source address");
	return (const union dp_ipv6 *)&ipv6_hdr->src_addr;
}
static __rte_always_inline
const union dp_ipv6 *dp_get_dst_ipv6(const struct rte_ipv6_hdr *ipv6_hdr)
{
	static_assert(sizeof(ipv6_hdr->dst_addr) == sizeof(union dp_ipv6), "Structure dp_ipv6 is not compatible with IPv6 destination address");
	return (const union dp_ipv6 *)&ipv6_hdr->dst_addr;
}

static __rte_always_inline
void dp_set_src_ipv6(struct rte_ipv6_hdr *ipv6_hdr, const union dp_ipv6 *ipv6)
{
	static_assert(sizeof(ipv6_hdr->src_addr) == sizeof(union dp_ipv6), "Structure dp_ipv6 is not compatible with IPv6 source address");
	dp_copy_ipv6((union dp_ipv6 *)ipv6_hdr->src_addr, ipv6);
}
static __rte_always_inline
void dp_set_dst_ipv6(struct rte_ipv6_hdr *ipv6_hdr, const union dp_ipv6 *ipv6)
{
	static_assert(sizeof(ipv6_hdr->dst_addr) == sizeof(union dp_ipv6), "Structure dp_ipv6 is not compatible with IPv6 destination address");
	dp_copy_ipv6((union dp_ipv6 *)ipv6_hdr->dst_addr, ipv6);
}

static __rte_always_inline
bool dp_is_ipv6_zero(const union dp_ipv6 *ipv6)
{
	return ipv6->_prefix == 0 && ipv6->_suffix == 0;
}

static __rte_always_inline
bool dp_ipv6_match(const union dp_ipv6 *l, const union dp_ipv6 *r)
{
	return l->_prefix == r->_prefix && l->_suffix == r->_suffix;
}

static __rte_always_inline
bool dp_masked_ipv6_match(const union dp_ipv6 *l, const union dp_ipv6 *r, const union dp_ipv6 *mask)
{
	return (l->_prefix & mask->_prefix) == (r->_prefix & mask->_prefix)
		&& (l->_suffix & mask->_suffix) == (r->_suffix & mask->_suffix);
}

int dp_ipv6_to_str(const union dp_ipv6 *ipv6, char *dest, int dest_len);
#define DP_IPV6_TO_STR(IPV6, DST) do { \
	static_assert(sizeof(DST) >= INET6_ADDRSTRLEN, "Insufficient buffer size for DP_IPV6_TO_STR()"); \
	dp_ipv6_to_str((IPV6), (DST), sizeof(DST)); \
	/* No return needed, all checks done statically. */ \
} while (0)

int dp_ipv4_to_str(uint32_t ipv4, char *dest, int dest_len);
#define DP_IPV4_TO_STR(IPV4, DST) do { \
	static_assert(sizeof(DST) >= INET_ADDRSTRLEN, "Insufficient buffer size for DP_IPV4_TO_STR()"); \
	dp_ipv4_to_str((IPV4), (DST), sizeof(DST)); \
	/* No return needed, all checks done statically. */ \
} while (0)

int dp_str_to_ipv4(const char *src, uint32_t *dest);
int dp_str_to_ipv6(const char *src, union dp_ipv6 *dest);

// TODO(plague): move NAT64 handling here (part of the above) + grep for [12] which means NAT64 ipv6 -> ipv4 conversion and wrap it


// structure for holding dual IP addresses
// made read-only without the right macro to prevent uninitialized bytes due to the the use of this structure in hash keys
struct dp_ip_address {
	union {
		union dp_ipv6		_ipv6;
		uint32_t			_ipv4;
		const union dp_ipv6	ipv6;
		const uint32_t		ipv4;
	};
	union {
		bool				_is_v6;
		const bool			is_v6;
	};
} __rte_packed;

static __rte_always_inline
int dp_ipv6_from_ipaddr(union dp_ipv6 *ipv6, const struct dp_ip_address *addr)
{
	if (!addr->is_v6)
		return DP_ERROR;

	ipv6->_prefix = addr->ipv6._prefix;
	ipv6->_suffix = addr->ipv6._suffix;
	return DP_OK;
}

static __rte_always_inline
void dp_copy_ipaddr(struct dp_ip_address *dst, const struct dp_ip_address *src)
{
	dst->_is_v6 = src->_is_v6;
	dst->_ipv6._prefix = src->ipv6._prefix;
	dst->_ipv6._suffix = src->ipv6._suffix;
}

static __rte_always_inline
void dp_set_ipaddr6(struct dp_ip_address *addr, const union dp_ipv6 *ipv6)
{
	addr->_is_v6 = true;
	addr->_ipv6._prefix = ipv6->_prefix;
	addr->_ipv6._suffix = ipv6->_suffix;
}

static __rte_always_inline
void dp_set_ipaddr4(struct dp_ip_address *addr, uint32_t ipv4)
{
	addr->_is_v6 = false;
	addr->_ipv6._prefix = addr->_ipv6._suffix = 0;
	addr->_ipv4 = ipv4;
}

int dp_ipaddr_to_str(const struct dp_ip_address *addr, char *dest, int dest_len);
#define DP_IPADDR_TO_STR(ADDR, DST) do { \
	static_assert(sizeof(DST) >= INET6_ADDRSTRLEN, "Insufficient buffer size for DP_IPADDR_TO_STR()"); \
	dp_ipaddr_to_str((ADDR), (DST), sizeof(DST)); \
} while (0)


// TODO(plague): I think this is broken for ARM
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
