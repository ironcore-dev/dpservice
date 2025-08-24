// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#include "dp_ipaddr.h"
#include <stdlib.h>
#include "dp_conf.h"


const union dp_ipv6 dp_empty_ipv6 = {
	.bytes = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }
};

const union dp_ipv6 dp_multicast_ipv6 = {
	.bytes = { 0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01 }
};

const union dp_ipv6 dp_nat64_prefix = {
	.bytes = { 0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }
};
const union dp_ipv6 dp_nat64_mask = {
	.bytes = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0 }
};


int dp_str_to_ipv4(const char *src, uint32_t *dest)
{
	struct in_addr addr;

	if (inet_pton(AF_INET, src, &addr) != 1)
		return DP_ERROR;

	*dest = ntohl(addr.s_addr);
	return DP_OK;
}

int dp_str_to_ipv6(const char *src, union dp_ipv6 *dest)
{
	// man(3): The address is converted to a struct in6_addr and copied to dst, which must be sizeof(struct in6_addr) (16) bytes (128 bits) long.
	// man(3): inet_pton() returns 1 on success
	static_assert(sizeof(struct in6_addr) == sizeof(*dest), "union dp_ipv6 is not compatible with inet_pton() requirements");
	return inet_pton(AF_INET6, src, dest) == 1 ? DP_OK : DP_ERROR;
}

int dp_ipv6_to_str(const union dp_ipv6 *ipv6, char *dest, int dest_len)
{
	if (!inet_ntop(AF_INET6, &ipv6->bytes, dest, dest_len))
		return -errno;

	return DP_OK;
}

int dp_ipv4_to_str(uint32_t ipv4, char *dest, int dest_len)
{
	rte_be32_t net_ipv4 = htonl(ipv4);

	if (!inet_ntop(AF_INET, &net_ipv4, dest, dest_len))
		return -errno;

	return DP_OK;
}

int dp_ipaddr_to_str(const struct dp_ip_address *addr, char *dest, int dest_len)
{
	union dp_ipv6 ipv6;

	if (DP_FAILED(dp_ipv6_from_ipaddr(&ipv6, addr)))
		return dp_ipv4_to_str(addr->ipv4, dest, dest_len);

	return dp_ipv6_to_str(&ipv6, dest, dest_len);
}


void dp_generate_ul_ipv6(union dp_ipv6 *dest, uint8_t addr_type)
{
	static uint32_t ul_counter = 0;

	dest->_ul.prefix = dp_conf_get_underlay_ip()->_prefix;  // Use the same prefix as the host
	dest->_ul.type = DP_UNDERLAY_ADDRESS_TYPE;
#ifdef ENABLE_UNDERLAY_TYPE
	dest->_ul.subtype = addr_type;
#else
	(void)addr_type;
	dest->_ul.subtype = 0;
#endif
	dest->_ul.flags = 0;
#ifdef ENABLE_STATIC_UNDERLAY_IP
	dest->_ul.random = 1;
#else
	dest->_ul.random = (uint8_t)(rand() % 256);

	// Start the counter from a random value to increase the randomness of dpservice startup
	if (ul_counter == 0)
		ul_counter = rand() % 256;
#endif
	dest->_ul.local = htonl(++ul_counter);
}
