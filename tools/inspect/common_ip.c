// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#include "common_ip.h"

#include <stdio.h>
#include <arpa/inet.h>

static char str_proto[16];

const char *get_str_ipproto(uint8_t proto)
{
	switch (proto) {
	case IPPROTO_IP:
		return "ip";
	case IPPROTO_ICMP:
		return "icmp";
	case IPPROTO_IPIP:
		return "ipip";
	case IPPROTO_TCP:
		return "tcp";
	case IPPROTO_UDP:
		return "udp";
	case IPPROTO_IPV6:
		return "ipv6";
	default:
		snprintf(str_proto, sizeof(str_proto), "%u", proto);
		return str_proto;
	}
}
