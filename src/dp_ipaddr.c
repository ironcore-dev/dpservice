#include "dp_ipaddr.h"

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
