// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#include "dp_nat.h"
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_common.h>
#include <rte_errno.h>
#include <rte_malloc.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include "dp_error.h"
#include "dp_internal_stats.h"
#include "dp_log.h"
#include "dp_mbuf_dyn.h"
#include "dp_port.h"
#include "dp_util.h"
#include "grpc/dp_grpc_responder.h"
#include "rte_flow/dp_rte_flow.h"
#include "protocols/dp_icmpv6.h"

#define DP_NAT_FULL_LOG_DELAY 5  /* seconds */

// This is based on the fact that neighnats are being put in the table along with local NAT/VIP
// To prevent it from being too large, this is assuming 2048 ports per NAT range (32 ranges/IP)
#define DP_NAT_TABLE_MAX (DP_MAX_VF_PORTS * 32)

TAILQ_HEAD(nat_head, nat_entry);

static struct rte_hash *ipv4_dnat_tbl = NULL;
static struct rte_hash *ipv4_snat_tbl = NULL;

static struct rte_hash *ipv4_netnat_portmap_tbl = NULL;
static struct rte_hash *ipv4_netnat_portoverload_tbl = NULL;
static struct nat_head nat_headp;

static uint64_t dp_nat_full_log_delay;

int dp_nat_init(int socket_id)
{
	ipv4_snat_tbl = dp_create_jhash_table(DP_NAT_TABLE_MAX, sizeof(struct nat_key),
										  DP_NAT_SNAT_TABLE_NAME, socket_id);
	if (!ipv4_snat_tbl)
		return DP_ERROR;

	ipv4_dnat_tbl = dp_create_jhash_table(DP_NAT_TABLE_MAX, sizeof(struct nat_key),
										  DP_NAT_DNAT_TABLE_NAME, socket_id);
	if (!ipv4_dnat_tbl)
		return DP_ERROR;

	ipv4_netnat_portmap_tbl = dp_create_jhash_table(DP_FLOW_TABLE_MAX, sizeof(struct netnat_portmap_key),
													DP_NAT_PORTMAP_TABLE_NAME, socket_id);

	if (!ipv4_netnat_portmap_tbl)
		return DP_ERROR;

	ipv4_netnat_portoverload_tbl = dp_create_jhash_table(DP_FLOW_TABLE_MAX, sizeof(struct netnat_portoverload_tbl_key),
														 DP_NAT_PORTOVERLOAD_TABLE_NAME, socket_id);

	if (!ipv4_netnat_portoverload_tbl)
		return DP_ERROR;

	TAILQ_INIT(&nat_headp);

	dp_nat_full_log_delay = rte_get_timer_hz() * DP_NAT_FULL_LOG_DELAY;

	return DP_OK;
}

void dp_nat_free(void)
{
	dp_free_jhash_table(ipv4_netnat_portoverload_tbl);
	dp_free_jhash_table(ipv4_netnat_portmap_tbl);
	dp_free_jhash_table(ipv4_dnat_tbl);
	dp_free_jhash_table(ipv4_snat_tbl);
}

struct snat_data *dp_get_iface_snat_data(uint32_t iface_ip, uint32_t vni)
{
	struct snat_data *data;
	struct nat_key nkey = {
		.ip = iface_ip,
		.vni = vni
	};
	int ret;

	ret = rte_hash_lookup_data(ipv4_snat_tbl, &nkey, (void **)&data);
	if (DP_FAILED(ret)) {
		if (ret != -ENOENT)
			DPS_LOG_ERR("Cannot lookup snat data", DP_LOG_RET(ret));
		return NULL;
	}

	return data;
}

static struct snat_data *dp_create_snat_data(uint32_t iface_ip, uint32_t vni)
{
	struct snat_data *data;
	struct nat_key nkey = {
		.ip = iface_ip,
		.vni = vni
	};

	data = rte_zmalloc("snat_val", sizeof(struct snat_data), RTE_CACHE_LINE_SIZE);
	if (!data)
		return NULL;

	if (DP_FAILED(rte_hash_add_key_data(ipv4_snat_tbl, &nkey, data))) {
		rte_free(data);
		return NULL;
	}

	return data;
}

static void dp_delete_snat_data(uint32_t iface_ip, uint32_t vni, struct snat_data *data)
{
	struct nat_key nkey = {
		.ip = iface_ip,
		.vni = vni
	};

	rte_free(data);
	if (DP_FAILED(rte_hash_del_key(ipv4_snat_tbl, &nkey)))
		DPS_LOG_WARNING("Failed to delete SNAT key");
}

int dp_set_iface_vip_ip(uint32_t iface_ip, uint32_t vip_ip, uint32_t vni,
						const union dp_ipv6 *ul_ipv6)
{
	struct snat_data *data;

	data = dp_get_iface_snat_data(iface_ip, vni);
	if (!data) {
		data = dp_create_snat_data(iface_ip, vni);
		if (!data)
			return DP_GRPC_ERR_SNAT_CREATE;
	} else if (data->vip_ip != 0)
		return DP_GRPC_ERR_SNAT_EXISTS;

	data->vip_ip = vip_ip;
	dp_copy_ipv6(&data->ul_vip_ip6, ul_ipv6);
	return DP_GRPC_OK;
}

int dp_set_iface_nat_ip(uint32_t iface_ip, uint32_t nat_ip, uint32_t vni, uint16_t min_port, uint16_t max_port,
						const union dp_ipv6 *ul_ipv6)
{
	struct snat_data *data;

	data = dp_get_iface_snat_data(iface_ip, vni);
	if (!data) {
		data = dp_create_snat_data(iface_ip, vni);
		if (!data)
			return DP_GRPC_ERR_SNAT_CREATE;
	} else if (data->nat_ip != 0)
		return DP_GRPC_ERR_SNAT_EXISTS;

	dp_copy_ipv6(&data->ul_nat_ip6, ul_ipv6);
	data->nat_ip = nat_ip;
	data->nat_port_range[0] = min_port;
	data->nat_port_range[1] = max_port;
	return DP_GRPC_OK;
}

int dp_del_iface_vip_ip(uint32_t iface_ip, uint32_t vni)
{
	struct snat_data *data;

	data = dp_get_iface_snat_data(iface_ip, vni);
	if (!data)
		return DP_GRPC_ERR_SNAT_NO_DATA;

	// NAT stil present, keep the data
	if (data->nat_ip != 0) {
		data->vip_ip = 0;
		return DP_GRPC_OK;
	}

	dp_delete_snat_data(iface_ip, vni, data);
	return DP_GRPC_OK;
}

int dp_del_iface_nat_ip(uint32_t iface_ip, uint32_t vni)
{
	struct snat_data *data;

	data = dp_get_iface_snat_data(iface_ip, vni);
	if (!data)
		return DP_GRPC_ERR_SNAT_NO_DATA;

	// VIP stil present, keep the data
	if (data->vip_ip != 0) {
		data->nat_ip = 0;
		data->nat_port_range[0] = 0;
		data->nat_port_range[1] = 0;
		return DP_GRPC_OK;
	}

	dp_delete_snat_data(iface_ip, vni, data);
	return DP_GRPC_OK;

}

struct dnat_data *dp_get_dnat_data(uint32_t d_ip, uint32_t vni)
{
	struct dnat_data *data;
	struct nat_key nkey = {
		.ip = d_ip,
		.vni = vni
	};

	// this can actually only fail on -ENOENT, because arguments will always be valid
	if (DP_FAILED(rte_hash_lookup_data(ipv4_dnat_tbl, &nkey, (void **)&data)))
		return NULL;

	return data;
}

int dp_set_dnat_ip(uint32_t d_ip, uint32_t dnat_ip, uint32_t vni)
{
	struct dnat_data *data;
	struct nat_key nkey = {
		.ip = d_ip,
		.vni = vni
	};

	data = dp_get_dnat_data(d_ip, vni);
	if (data)
		return DP_GRPC_ERR_DNAT_EXISTS;

	data = rte_zmalloc("dnat_val", sizeof(struct dnat_data), RTE_CACHE_LINE_SIZE);
	if (!data)
		return DP_GRPC_ERR_DNAT_CREATE;

	if (DP_FAILED(rte_hash_add_key_data(ipv4_dnat_tbl, &nkey, data))) {
		rte_free(data);
		return DP_GRPC_ERR_DNAT_CREATE;
	}

	data->dnat_ip = dnat_ip;
	return DP_GRPC_OK;
}

int dp_del_dnat_ip(uint32_t d_ip, uint32_t vni)
{
	struct dnat_data *data;
	struct nat_key nkey = {
		.ip = d_ip,
		.vni = vni
	};
	hash_sig_t hash = rte_hash_hash(ipv4_dnat_tbl, &nkey);

	if (DP_FAILED(rte_hash_lookup_with_hash_data(ipv4_dnat_tbl, &nkey, hash, (void **)&data)))
		return DP_GRPC_ERR_DNAT_NO_DATA;

	rte_free(data);
	if (DP_FAILED(rte_hash_del_key_with_hash(ipv4_dnat_tbl, &nkey, hash)))
		DPS_LOG_WARNING("Failed to delete DNAT key", DP_LOG_VNI(vni), DP_LOG_IPV4(d_ip));

	return DP_GRPC_OK;
}

void dp_nat_chg_ip(struct dp_flow *df, struct rte_ipv4_hdr *ipv4_hdr,
				   struct rte_mbuf *m)
{
	struct rte_udp_hdr *udp_hdr;
	struct rte_tcp_hdr *tcp_hdr;

	ipv4_hdr->hdr_checksum = 0;
	m->ol_flags |= RTE_MBUF_F_TX_IPV4;
	m->ol_flags |= RTE_MBUF_F_TX_IP_CKSUM;
	m->tx_offload = 0;
	m->l2_len = sizeof(struct rte_ether_hdr);
	m->l3_len = rte_ipv4_hdr_len(ipv4_hdr);
	m->l4_len = 0;

	switch (df->l4_type) {
		case IPPROTO_TCP:
			tcp_hdr =  (struct rte_tcp_hdr *)(ipv4_hdr + 1);
			tcp_hdr->cksum = 0;
			m->ol_flags |= RTE_MBUF_F_TX_TCP_CKSUM;
			m->l4_len = DP_TCP_HDR_LEN(tcp_hdr);
		break;
		case IPPROTO_UDP:
			udp_hdr =  (struct rte_udp_hdr *)(ipv4_hdr + 1);
			udp_hdr->dgram_cksum = 0;
			m->ol_flags |= RTE_MBUF_F_TX_UDP_CKSUM;
			m->l4_len = sizeof(struct rte_udp_hdr);
		break;
		case IPPROTO_ICMP:
			m->l4_len = sizeof(struct rte_icmp_hdr);
		break;
		default:
		break;
	}
}

static void dp_calculate_icmp_checksum(struct rte_icmp_hdr *icmp_hdr, size_t icmp_len)
{
	uint32_t sum = 0;
	uint16_t word;
	uint8_t *ptr = (uint8_t *)icmp_hdr;

	icmp_hdr->icmp_cksum = 0;

	for (size_t i = 0; i < icmp_len; i += 2) {
		word = (uint16_t)((uint16_t)ptr[i] | ((uint16_t)ptr[i + 1] << 8));
		sum += word;
	}

	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);

	icmp_hdr->icmp_cksum = ~((uint16_t)sum);
}

int dp_nat_chg_ipv6_to_ipv4_hdr(struct dp_flow *df, struct rte_mbuf *m, uint32_t nat_ip, rte_be32_t *dest_ip /* out */)
{
	struct rte_ether_hdr *eth_hdr;
	struct rte_ipv6_hdr *ipv6_hdr;
	struct rte_ipv4_hdr *ipv4_hdr;
	struct rte_icmp_hdr *icmp_hdr;
	struct rte_udp_hdr *udp_hdr;
	struct rte_tcp_hdr *tcp_hdr;
	uint8_t l4_proto;

	eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
	eth_hdr->ether_type = htons(RTE_ETHER_TYPE_IPV4);

	ipv6_hdr = dp_get_ipv6_hdr(m);
	*dest_ip = dp_get_ipv6_nat64(dp_get_dst_ipv6(ipv6_hdr));
	l4_proto = ipv6_hdr->proto;

	// Adjust the packet data to fit IPv4
	if (rte_pktmbuf_adj(m, sizeof(struct rte_ipv6_hdr) - sizeof(struct rte_ipv4_hdr)) == NULL)
		return DP_ERROR;

	// Move the Ethernet header to just before the IPv4 header
	// The access to the "shortened" mbuf memory is intentional and is allowed for mbufs
	memmove(rte_pktmbuf_mtod(m, uint8_t *), eth_hdr, sizeof(struct rte_ether_hdr));

	// Setup the new IPv4 header
	ipv4_hdr = dp_get_ipv4_hdr(m);
	ipv4_hdr->version_ihl = 0x45;
	ipv4_hdr->type_of_service = (uint8_t)((ntohl(ipv6_hdr->vtc_flow) >> 20) & 0xFF);
	ipv4_hdr->total_length = htons(rte_pktmbuf_data_len(m) - (uint16_t)sizeof(struct rte_ether_hdr));
	ipv4_hdr->packet_id = 0;
	ipv4_hdr->fragment_offset = 0;
	ipv4_hdr->time_to_live = ipv6_hdr->hop_limits;
	ipv4_hdr->next_proto_id = l4_proto;
	ipv4_hdr->src_addr = htonl(nat_ip);
	ipv4_hdr->dst_addr = *dest_ip;
	ipv4_hdr->hdr_checksum = 0;

	m->packet_type = (m->packet_type & ~RTE_PTYPE_L3_MASK) | RTE_PTYPE_L3_IPV4;
	m->ol_flags |= RTE_MBUF_F_TX_IPV4;
	m->ol_flags |= RTE_MBUF_F_TX_IP_CKSUM;
	m->tx_offload = 0;
	m->l2_len = sizeof(struct rte_ether_hdr);
	m->l3_len = rte_ipv4_hdr_len(ipv4_hdr);
	m->l4_len = 0;
	df->l3_type = RTE_ETHER_TYPE_IPV4;

	switch (df->l4_type) {
	case IPPROTO_TCP:
		tcp_hdr =  (struct rte_tcp_hdr *)(ipv4_hdr + 1);
		tcp_hdr->cksum = 0;
		m->ol_flags |= RTE_MBUF_F_TX_TCP_CKSUM;
		m->l4_len = DP_TCP_HDR_LEN(tcp_hdr);
	break;
	case IPPROTO_UDP:
		udp_hdr =  (struct rte_udp_hdr *)(ipv4_hdr + 1);
		udp_hdr->dgram_cksum = 0;
		m->ol_flags |= RTE_MBUF_F_TX_UDP_CKSUM;
		m->l4_len = sizeof(struct rte_udp_hdr);
	break;
	case IPPROTO_ICMPV6:
		df->l4_type = IPPROTO_ICMP;
		ipv4_hdr->next_proto_id = IPPROTO_ICMP;
		m->l4_len = sizeof(struct rte_icmp_hdr);
		m->l4_type = IPPROTO_ICMP;

		icmp_hdr = (struct rte_icmp_hdr *)(ipv4_hdr + 1);
		icmp_hdr->icmp_code = 0;
		if (icmp_hdr->icmp_type == DP_ICMPV6_ECHO_REQUEST)
			icmp_hdr->icmp_type = RTE_IP_ICMP_ECHO_REQUEST;
		else if (icmp_hdr->icmp_type == DP_ICMPV6_ECHO_REPLY)
			icmp_hdr->icmp_type = RTE_IP_ICMP_ECHO_REPLY;
		else
			return DP_ERROR; //Drop unsupported ICMP Types for the time being
		dp_calculate_icmp_checksum(icmp_hdr, rte_be_to_cpu_16(ipv4_hdr->total_length) - ((ipv4_hdr->version_ihl & 0x0F) * 4));
	break;
	default:
		return DP_ERROR;
	}

	return DP_OK;
}

int dp_nat_chg_ipv4_to_ipv6_hdr(struct dp_flow *df, struct rte_mbuf *m, const union dp_ipv6 *ipv6_addr)
{
	struct rte_ether_hdr *eth_hdr;
	struct rte_ipv4_hdr *ipv4_hdr;
	struct rte_ipv6_hdr *ipv6_hdr;
	struct rte_icmp_hdr *icmp_hdr;
	struct rte_udp_hdr *udp_hdr;
	struct rte_tcp_hdr *tcp_hdr;
	union dp_ipv6 src_nat64;
	rte_be32_t src_ipv4;
	uint8_t l4_proto;

	eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
	eth_hdr->ether_type = htons(RTE_ETHER_TYPE_IPV6);

	ipv4_hdr = dp_get_ipv4_hdr(m);
	src_ipv4 = ipv4_hdr->src_addr;
	l4_proto = ipv4_hdr->next_proto_id;

	// Adjust the packet data to fit IPv6
	if (rte_pktmbuf_prepend(m, sizeof(struct rte_ipv6_hdr) - sizeof(struct rte_ipv4_hdr)) == NULL)
		return DP_ERROR;

	// Move the Ethernet header to just before the IPv6 header
	memmove(rte_pktmbuf_mtod(m, uint8_t *), eth_hdr, sizeof(struct rte_ether_hdr));

	// Setup the new IPv6 header
	ipv6_hdr = dp_get_ipv6_hdr(m);
	ipv6_hdr->vtc_flow = rte_cpu_to_be_32((6 << 28) | (ipv4_hdr->type_of_service << 20));
	ipv6_hdr->payload_len = htons(rte_pktmbuf_data_len(m) - (uint16_t)sizeof(struct rte_ether_hdr) - (uint16_t)sizeof(struct rte_ipv6_hdr));
	ipv6_hdr->proto = l4_proto;
	ipv6_hdr->hop_limits = ipv4_hdr->time_to_live;

	// Set the source and destination IPv6 addresses
	dp_set_ipv6_nat64(&src_nat64, src_ipv4);
	dp_set_src_ipv6(ipv6_hdr, &src_nat64);
	dp_set_dst_ipv6(ipv6_hdr, ipv6_addr);
	dp_copy_ipv6(&df->dst.dst_addr6, ipv6_addr);

	m->packet_type = (m->packet_type & ~RTE_PTYPE_L3_MASK) | RTE_PTYPE_L3_IPV6;
	m->ol_flags |= RTE_MBUF_F_TX_IPV6;
	m->l2_len = sizeof(struct rte_ether_hdr);
	m->l3_len = sizeof(struct rte_ipv6_hdr);
	m->l4_len = 0;

	switch (df->l4_type) {
	case IPPROTO_TCP:
		tcp_hdr = (struct rte_tcp_hdr *)(ipv6_hdr + 1);
		tcp_hdr->cksum = 0;
		m->ol_flags |= RTE_MBUF_F_TX_TCP_CKSUM;
		m->l4_len = DP_TCP_HDR_LEN(tcp_hdr);
		break;
	case IPPROTO_UDP:
		udp_hdr = (struct rte_udp_hdr *)(ipv6_hdr + 1);
		udp_hdr->dgram_cksum = 0;
		m->ol_flags |= RTE_MBUF_F_TX_UDP_CKSUM;
		m->l4_len = sizeof(struct rte_udp_hdr);
		break;
	case IPPROTO_ICMP:
		df->l4_type = IPPROTO_ICMPV6;
		m->l4_len = sizeof(struct rte_icmp_hdr);
		ipv6_hdr->proto = IPPROTO_ICMPV6;
		icmp_hdr = (struct rte_icmp_hdr *)(ipv6_hdr + 1);
		icmp_hdr->icmp_code = 0;
		icmp_hdr->icmp_cksum = 0;

		if (icmp_hdr->icmp_type == RTE_IP_ICMP_ECHO_REQUEST)
			icmp_hdr->icmp_type = DP_ICMPV6_ECHO_REQUEST;
		else if (icmp_hdr->icmp_type == RTE_IP_ICMP_ECHO_REPLY)
			icmp_hdr->icmp_type = DP_ICMPV6_ECHO_REPLY;
		else
			return DP_ERROR; //Drop unsupported ICMP Types for the time being
		icmp_hdr->icmp_cksum = rte_ipv6_udptcp_cksum(ipv6_hdr, icmp_hdr);
		break;
	default:
		return DP_ERROR;
	}
	return DP_OK;
}

static __rte_always_inline bool dp_is_same_network_nat_entry(const struct nat_entry *entry,
														uint32_t nat_ip, uint32_t vni,
														uint16_t min_port, uint16_t max_port)
{
	return entry->vni == vni
		&& entry->nat_ip == nat_ip
		&& entry->port_range[0] == min_port
		&& entry->port_range[1] == max_port;
}

static __rte_always_inline bool dp_is_network_nat_entry_port_overlap(const struct nat_entry *entry, uint32_t nat_ip, uint16_t min_port, uint16_t max_port)
{
	return entry->nat_ip == nat_ip && (max_port > entry->port_range[0]) && (min_port < entry->port_range[1]);
}

// check if a port falls into the range of external nat's port range
static __rte_always_inline bool dp_is_network_nat_port(const struct nat_entry *entry,
													   uint32_t nat_ip, uint32_t vni,
													   uint16_t port)
{
	return entry->vni == vni
		&& entry->nat_ip == nat_ip
		&& entry->port_range[0] <= port
		&& entry->port_range[1] > port;
}

void dp_del_vip_from_dnat(uint32_t d_ip, uint32_t vni)
{
	struct nat_entry *entry;

	// only delete the DNAT entry when this is the only range present for this IP
	// (i.e. if there still is an entry in the list, do nothing!)
	for (entry = TAILQ_FIRST(&nat_headp); entry != NULL; entry = TAILQ_NEXT(entry, entries))
		if (entry->vni == vni && entry->nat_ip == d_ip)
			return;

	dp_del_dnat_ip(d_ip, vni);
}

int dp_add_network_nat_entry(uint32_t nat_ip, uint32_t vni, uint16_t min_port, uint16_t max_port,
							 const union dp_ipv6 *ul_ipv6)
{
	struct nat_entry *next, *new_entry;

	TAILQ_FOREACH(next, &nat_headp, entries) {
		if (dp_is_network_nat_entry_port_overlap(next, nat_ip, min_port, max_port)) {
			DPS_LOG_WARNING("Cannot add a nat entry that has an overlapping port range with an existing one",
							DP_LOG_IPV4(nat_ip), DP_LOG_VNI(vni), DP_LOG_MINPORT(min_port), DP_LOG_MAXPORT(max_port));
			return DP_GRPC_ERR_ALREADY_EXISTS;
		}
	}

	new_entry = rte_zmalloc("network_nat_array", sizeof(struct nat_entry), RTE_CACHE_LINE_SIZE);
	if (!new_entry) {
		DPS_LOG_ERR("Failed to allocate nat entry", DP_LOG_IPV4(nat_ip), DP_LOG_VNI(vni),
					DP_LOG_MINPORT(min_port), DP_LOG_MAXPORT(max_port));
		return DP_GRPC_ERR_OUT_OF_MEMORY;
	}

	new_entry->nat_ip = nat_ip;
	new_entry->vni = vni;
	new_entry->port_range[0] = min_port;
	new_entry->port_range[1] = max_port;
	dp_copy_ipv6(&new_entry->dst_ipv6, ul_ipv6);

	TAILQ_INSERT_TAIL(&nat_headp, new_entry, entries);

	return DP_GRPC_OK;

}

int dp_del_network_nat_entry(uint32_t nat_ip, uint32_t vni, uint16_t min_port, uint16_t max_port)
{
	struct nat_entry *item, *tmp_item;

	for (item = TAILQ_FIRST(&nat_headp); item != NULL; item = tmp_item) {
		tmp_item = TAILQ_NEXT(item, entries);
		if (dp_is_same_network_nat_entry(item, nat_ip, vni, min_port, max_port)) {
			TAILQ_REMOVE(&nat_headp, item, entries);
			rte_free(item);
			return DP_GRPC_OK;
		}
	}
	return DP_GRPC_ERR_NOT_FOUND;
}

const union dp_ipv6 *dp_lookup_network_nat_underlay_ip(struct dp_flow *df)
{
	struct nat_entry *current;
	uint16_t dst_port;
	uint32_t dst_vni;
	uint32_t dst_ip;

	dst_ip = ntohl(df->dst.dst_addr);
	dst_vni = df->tun_info.dst_vni;
	if (df->l4_type == IPPROTO_ICMP || df->l4_type == IPPROTO_ICMPV6)
		dst_port = ntohs(df->l4_info.icmp_field.icmp_identifier);
	else
		dst_port = ntohs(df->l4_info.trans_port.dst_port);

	TAILQ_FOREACH(current, &nat_headp, entries) {
		if (dp_is_network_nat_port(current, dst_ip, dst_vni, dst_port))
			return &current->dst_ipv6;
	}
	return NULL;
}

int dp_allocate_network_snat_port(struct snat_data *snat_data, struct dp_flow *df, uint32_t vni)
{
	struct netnat_portoverload_tbl_key portoverload_tbl_key;
	struct netnat_portmap_key portmap_key;
	struct netnat_portmap_data *portmap_data;
	uint16_t min_port, max_port, allocated_port = 0, tmp_port;
	uint32_t iface_src_info_hash;
	int ret;
	bool need_to_find_new_port = true;
	uint32_t iface_src_ip = ntohl(df->src.src_addr);
	uint16_t iface_src_port;
	uint64_t timestamp;

	if (df->l3_type == RTE_ETHER_TYPE_IPV4) {
		dp_set_ipaddr4(&portmap_key.src_ip, iface_src_ip);
		portoverload_tbl_key.dst_ip = ntohl(df->dst.dst_addr);
	} else if (df->l3_type == RTE_ETHER_TYPE_IPV6) {
		dp_set_ipaddr6(&portmap_key.src_ip, &df->src.src_addr6);
		portoverload_tbl_key.dst_ip = ntohl(dp_get_ipv6_nat64(&df->dst.dst_addr6));
	} else {
		return DP_GRPC_ERR_BAD_IPVER;
	}

	if (df->l4_type == IPPROTO_ICMP || df->l4_type == IPPROTO_ICMPV6)
		iface_src_port = ntohs(df->l4_info.icmp_field.icmp_identifier);
	else
		iface_src_port = ntohs(df->l4_info.trans_port.src_port);

	portmap_key.iface_src_port = iface_src_port;
	portmap_key.vni = vni;

	portoverload_tbl_key.nat_ip = snat_data->nat_ip;
	portoverload_tbl_key.l4_type = df->l4_type;
	if (df->l4_type == IPPROTO_ICMP || df->l4_type == IPPROTO_ICMPV6)
		portoverload_tbl_key.dst_port = ntohs(df->l4_info.icmp_field.icmp_identifier);
	else
		portoverload_tbl_key.dst_port = ntohs(df->l4_info.trans_port.dst_port);

	ret = rte_hash_lookup_data(ipv4_netnat_portmap_tbl, &portmap_key, (void **)&portmap_data);
	if (ret != -ENOENT) {
		if (DP_FAILED(ret)) {
			DPS_LOG_ERR("Cannot lookup ipv4 portmap key", DP_LOG_RET(ret));
			return ret;
		}

		portoverload_tbl_key.nat_port = portmap_data->nat_port;
		ret = rte_hash_lookup(ipv4_netnat_portoverload_tbl, &portoverload_tbl_key);

		if (likely(ret == -ENOENT)) {
			portmap_data->flow_cnt++;
			allocated_port = portmap_data->nat_port;
			need_to_find_new_port = false;
		} else if (DP_FAILED(ret)) {
			DPS_LOG_ERR("Cannot lookup ipv4 port overload key for an existing nat port", DP_LOG_RET(ret));
			return ret;
		}
	}

	if (need_to_find_new_port) {
		min_port = snat_data->nat_port_range[0];
		max_port = snat_data->nat_port_range[1];

		iface_src_info_hash = (uint32_t)rte_hash_hash(ipv4_netnat_portmap_tbl, &portmap_key);

		for (uint16_t p = 0; p < max_port - min_port; p++) {
			tmp_port = min_port + (uint16_t)((iface_src_info_hash + p) % (uint32_t)(max_port - min_port));
			portoverload_tbl_key.nat_port = tmp_port;
			ret = rte_hash_lookup(ipv4_netnat_portoverload_tbl, &portoverload_tbl_key);
			if (ret == -ENOENT) {
				allocated_port = tmp_port;
				break;
			} else if (DP_FAILED(ret)) {
				DPS_LOG_ERR("Cannot lookup ipv4 port overload key", DP_LOG_RET(ret));
				return ret;
			}
		}

		if (!allocated_port) {
			// This is normal once the port range gets saturated, but still helpful in logs.
			// Therefore the log must be present, just rate-limited (per interface).
			timestamp = rte_rdtsc();
			if (timestamp > snat_data->log_timestamp + dp_nat_full_log_delay) {
				snat_data->log_timestamp = timestamp;
				DPS_LOG_WARNING("NAT portmap range is full",
								DP_LOG_IPV4(snat_data->nat_ip),
								DP_LOG_VNI(vni), DP_LOG_SRC_IPV4(iface_src_ip),
								DP_LOG_SRC_PORT(iface_src_port));
			}
			return DP_ERROR;
		}

	}

	ret = rte_hash_add_key(ipv4_netnat_portoverload_tbl, (const void *)&portoverload_tbl_key);
	if (DP_FAILED(ret)) {
		DPS_LOG_ERR("Failed to add ipv4 network nat port overload key", DP_LOG_RET(ret));
		return ret;
	}

	if (need_to_find_new_port) {
		portmap_data = rte_zmalloc("netnat_portmap_val", sizeof(struct netnat_portmap_data), RTE_CACHE_LINE_SIZE);
		portmap_data->nat_ip = snat_data->nat_ip;
		portmap_data->nat_port = allocated_port;
		portmap_data->flow_cnt++;

		ret = rte_hash_add_key_data(ipv4_netnat_portmap_tbl, (const void *)&portmap_key, (void *)portmap_data);
		if (DP_FAILED(ret)) {
			rte_free(portmap_data);
			DPS_LOG_ERR("Failed to add ipv4 network nat portmap data", DP_LOG_RET(ret));
			return ret;
		}
	}

	return allocated_port;
}

int dp_remove_network_snat_port(const struct flow_value *cntrack)
{
	struct netnat_portmap_key portmap_key = {0};
	struct netnat_portoverload_tbl_key portoverload_tbl_key = {0};
	const struct flow_key *flow_key_org = &cntrack->flow_key[DP_FLOW_DIR_ORG];
	const struct flow_key *flow_key_reply = &cntrack->flow_key[DP_FLOW_DIR_REPLY];
	struct netnat_portmap_data *portmap_data;
	struct dp_port *created_port;
	union dp_ipv6 dst_nat64;
	int ret;

	if (unlikely(flow_key_reply->l3_dst.is_v6)) {
		DPS_LOG_ERR("NAT reply flow key with IPv6 address", DP_LOG_IPV6(flow_key_reply->l3_dst.ipv6));
		return DP_ERROR;
	}

	if (DP_FAILED(dp_ipv6_from_ipaddr(&dst_nat64, &flow_key_org->l3_dst)))
		portoverload_tbl_key.dst_ip = flow_key_org->l3_dst.ipv4;
	else
		portoverload_tbl_key.dst_ip = ntohl(dp_get_ipv6_nat64(&dst_nat64));
	portoverload_tbl_key.nat_ip = flow_key_reply->l3_dst.ipv4;
	portoverload_tbl_key.nat_port = flow_key_reply->port_dst;
	portoverload_tbl_key.dst_port = flow_key_org->port_dst;
	portoverload_tbl_key.l4_type = flow_key_org->proto;

	// forcefully delete, if it was never there, it's fine
	ret = rte_hash_del_key(ipv4_netnat_portoverload_tbl, &portoverload_tbl_key);
	if (DP_FAILED(ret) && ret != -ENOENT)
		return ret;

	dp_copy_ipaddr(&portmap_key.src_ip, &flow_key_org->l3_src);
	portmap_key.iface_src_port = flow_key_org->src.port_src;
	portmap_key.vni = cntrack->nf_info.vni;
	if (flow_key_org->proto == IPPROTO_ICMP || flow_key_org->proto == IPPROTO_ICMPV6)
		//flow_key[DP_FLOW_DIR_ORG].port_dst is already a converted icmp identifier
		portmap_key.iface_src_port = flow_key_org->port_dst;
	else
		portmap_key.iface_src_port = flow_key_org->src.port_src;

	ret = rte_hash_lookup_data(ipv4_netnat_portmap_tbl, &portmap_key, (void **)&portmap_data);
	if (DP_FAILED(ret))
		return ret == -ENOENT ? DP_OK : ret;

	portmap_data->flow_cnt--;
	if (portmap_data->flow_cnt == 0) {
		ret = rte_hash_del_key(ipv4_netnat_portmap_tbl, &portmap_key);
		if (DP_FAILED(ret)) {
			portmap_data->flow_cnt++;
			DPS_LOG_ERR("Cannot delete portmap key", DP_LOG_RET(ret));
			return DP_ERROR;
		}
		rte_free(portmap_data);
	}

	created_port = dp_get_port_by_id(cntrack->created_port_id);
	if (!created_port)
		return DP_ERROR;

	DP_STATS_NAT_DEC_USED_PORT_CNT(created_port);

	return DP_OK;
}

int dp_list_nat_local_entries(uint32_t nat_ip, struct dp_grpc_responder *responder)
{
	const struct nat_key *nkey;
	struct snat_data *data;
	uint32_t index = 0;
	int32_t ret;
	struct dpgrpc_nat *reply;

	if (rte_hash_count(ipv4_snat_tbl) == 0)
		return DP_GRPC_OK;

	dp_grpc_set_multireply(responder, sizeof(*reply));

	while ((ret = rte_hash_iterate(ipv4_snat_tbl, (const void **)&nkey, (void **)&data, &index)) != -ENOENT) {
		if (DP_FAILED(ret))
			return DP_GRPC_ERR_ITERATOR;

		// VIP entries use the same table and have data->nat_ip set to 0 so they would match when nat_ip is 0
		if (data->nat_ip != 0 && (nat_ip == 0 || data->nat_ip == nat_ip)) {
			reply = dp_grpc_add_reply(responder);
			if (!reply)
				return DP_GRPC_ERR_OUT_OF_MEMORY;
			reply->min_port = data->nat_port_range[0];
			reply->max_port = data->nat_port_range[1];
			dp_set_ipaddr4(&reply->natted_ip, nkey->ip);
			reply->vni = nkey->vni;
			dp_set_ipaddr4(&reply->addr, data->nat_ip);
		}
	}
	return DP_GRPC_OK;
}

int dp_list_nat_neigh_entries(uint32_t nat_ip, struct dp_grpc_responder *responder)
{
	struct nat_entry *current;
	struct dpgrpc_nat *reply;

	dp_grpc_set_multireply(responder, sizeof(*reply));

	TAILQ_FOREACH(current, &nat_headp, entries) {
		if (nat_ip == 0 || current->nat_ip == nat_ip) {
			reply = dp_grpc_add_reply(responder);
			if (!reply)
				return DP_GRPC_ERR_OUT_OF_MEMORY;
			reply->min_port = current->port_range[0];
			reply->max_port = current->port_range[1];
			reply->vni = current->vni;
			dp_copy_ipv6(&reply->ul_addr6, &current->dst_ipv6);
			dp_set_ipaddr4(&reply->addr, current->nat_ip);
		}
	}
	return DP_GRPC_OK;
}

static int dp_del_dnat_by_vni(uint32_t vni)
{
	struct dnat_data *data;
	const struct nat_key *key;
	uint32_t iter = 0;
	int	ret;

	while ((ret = rte_hash_iterate(ipv4_dnat_tbl, (const void **)&key, (void **)&data, &iter)) != -ENOENT) {
		if (DP_FAILED(ret)) {
			DPS_LOG_ERR("Iterating dnat table to remove VNI failed", DP_LOG_RET(ret), DP_LOG_VNI(vni));
			return ret;
		}
		if (key->vni == vni) {
			rte_free(data);
			ret = rte_hash_del_key(ipv4_dnat_tbl, key);
			if (DP_FAILED(ret))
				DPS_LOG_WARNING("Failed to delete DNAT key", DP_LOG_RET(ret), DP_LOG_VNI(vni), DP_LOG_IPV4(key->ip));
		}
	}
	return DP_OK;
}

void dp_del_all_neigh_nat_entries_in_vni(uint32_t vni)
{
	struct nat_entry *item, *tmp_item;

	for (item = TAILQ_FIRST(&nat_headp); item != NULL; item = tmp_item) {
		tmp_item = TAILQ_NEXT(item, entries);
		if ((item->vni == vni) || (vni == DP_NETWORK_NAT_ALL_VNI)) {
			TAILQ_REMOVE(&nat_headp, item, entries);
			rte_free(item);
		}
	}

	if (DP_FAILED(dp_del_dnat_by_vni(vni)))
		DPS_LOG_WARNING("Not all DNAT entries removed", DP_LOG_VNI(vni));
}
