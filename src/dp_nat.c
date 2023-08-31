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
#include "grpc/dp_grpc_responder.h"
#include "rte_flow/dp_rte_flow.h"

TAILQ_HEAD(network_nat_head, network_nat_entry);

static struct rte_hash *ipv4_dnat_tbl = NULL;
static struct rte_hash *ipv4_snat_tbl = NULL;

static struct rte_hash *ipv4_netnat_portmap_tbl = NULL;
static struct rte_hash *ipv4_netnat_portoverload_tbl = NULL;
static struct network_nat_head nat_headp;

int dp_nat_init(int socket_id)
{
	ipv4_snat_tbl = dp_create_jhash_table(DP_NAT_TABLE_MAX, sizeof(struct nat_key),
										  "ipv4_snat_table", socket_id);
	if (!ipv4_snat_tbl)
		return DP_ERROR;

	ipv4_dnat_tbl = dp_create_jhash_table(DP_NAT_TABLE_MAX, sizeof(struct nat_key),
										  "ipv4_dnat_table", socket_id);
	if (!ipv4_dnat_tbl)
		return DP_ERROR;

	ipv4_netnat_portmap_tbl = dp_create_jhash_table(FLOW_MAX, sizeof(struct netnat_portmap_key),
												  "ipv4_netnat_portmap_table", socket_id);

	if (!ipv4_netnat_portmap_tbl)
		return DP_ERROR;

	ipv4_netnat_portoverload_tbl = dp_create_jhash_table(FLOW_MAX, sizeof(struct netnat_portoverload_tbl_key),
												  "ipv4_netnat_portoverload_tbl", socket_id);

	if (!ipv4_netnat_portoverload_tbl)
		return DP_ERROR;

	TAILQ_INIT(&nat_headp);

	return DP_OK;
}

void dp_nat_free(void)
{
	dp_free_jhash_table(ipv4_netnat_portoverload_tbl);
	dp_free_jhash_table(ipv4_netnat_portmap_tbl);
	dp_free_jhash_table(ipv4_dnat_tbl);
	dp_free_jhash_table(ipv4_snat_tbl);
}

struct snat_data *dp_get_vm_snat_data(uint32_t vm_ip, uint32_t vni)
{
	struct snat_data *data;
	struct nat_key nkey = {
		.ip = vm_ip,
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

static struct snat_data *dp_create_vm_snat_data(uint32_t vm_ip, uint32_t vni)
{
	struct snat_data *data;
	struct nat_key nkey = {
		.ip = vm_ip,
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

static void dp_delete_vm_snat_data(uint32_t vm_ip, uint32_t vni, struct snat_data *data)
{
	struct nat_key nkey = {
		.ip = vm_ip,
		.vni = vni
	};

	rte_free(data);
	if (DP_FAILED(rte_hash_del_key(ipv4_snat_tbl, &nkey)))
		DPS_LOG_WARNING("Failed to delete SNAT key");
}

int dp_set_vm_snat_ip(uint32_t vm_ip, uint32_t s_ip, uint32_t vni, uint8_t ul_ipv6[DP_VNF_IPV6_ADDR_SIZE])
{
	struct snat_data *data;

	data = dp_get_vm_snat_data(vm_ip, vni);
	if (!data) {
		data = dp_create_vm_snat_data(vm_ip, vni);
		if (!data)
			return DP_GRPC_ERR_SNAT_CREATE;
	} else if (data->vip_ip != 0)
		return DP_GRPC_ERR_SNAT_EXISTS;

	data->vip_ip = s_ip;
	rte_memcpy(data->ul_ip6, ul_ipv6, sizeof(data->ul_ip6));
	return DP_GRPC_OK;
}

int dp_set_vm_network_snat_ip(uint32_t vm_ip, uint32_t s_ip, uint32_t vni, uint16_t min_port,
							  uint16_t max_port, uint8_t ul_ipv6[DP_VNF_IPV6_ADDR_SIZE])
{
	struct snat_data *data;

	data = dp_get_vm_snat_data(vm_ip, vni);
	if (!data) {
		data = dp_create_vm_snat_data(vm_ip, vni);
		if (!data)
			return DP_GRPC_ERR_SNAT_CREATE;
	} else if (data->network_nat_ip != 0)
		return DP_GRPC_ERR_SNAT_EXISTS;

	rte_memcpy(data->ul_nat_ip6, ul_ipv6, sizeof(data->ul_ip6));
	data->network_nat_ip = s_ip;
	data->network_nat_port_range[0] = min_port;
	data->network_nat_port_range[1] = max_port;
	return DP_GRPC_OK;
}

int dp_del_vm_snat_ip(uint32_t vm_ip, uint32_t vni)
{
	struct snat_data *data;

	data = dp_get_vm_snat_data(vm_ip, vni);
	if (!data)
		return DP_GRPC_ERR_SNAT_NO_DATA;

	// NAT stil present, keep the data
	if (data->network_nat_ip != 0) {
		data->vip_ip = 0;
		return DP_GRPC_OK;
	}

	dp_delete_vm_snat_data(vm_ip, vni, data);
	return DP_GRPC_OK;
}

int dp_del_vm_network_snat_ip(uint32_t vm_ip, uint32_t vni)
{
	struct snat_data *data;

	data = dp_get_vm_snat_data(vm_ip, vni);
	if (!data)
		return DP_GRPC_ERR_SNAT_NO_DATA;

	// VIP stil present, keep the data
	if (data->vip_ip != 0) {
		data->network_nat_ip = 0;
		data->network_nat_port_range[0] = 0;
		data->network_nat_port_range[1] = 0;
		return DP_GRPC_OK;
	}

	dp_delete_vm_snat_data(vm_ip, vni, data);
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

	if (DP_FAILED(rte_hash_lookup_data(ipv4_dnat_tbl, &nkey, (void **)&data)))
		return DP_GRPC_ERR_DNAT_NO_DATA;

	rte_free(data);
	if (DP_FAILED(rte_hash_del_key(ipv4_dnat_tbl, &nkey)))
		DPS_LOG_WARNING("Failed to delete DNAT key");

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

	switch (df->l4_type)
	{
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


static __rte_always_inline bool dp_is_network_nat_ip(struct network_nat_entry *entry,
													 uint32_t nat_ipv4,
													 uint8_t nat_ipv6[DP_VNF_IPV6_ADDR_SIZE], uint32_t vni)
{
	return entry->vni == vni
			&& ((nat_ipv4 != 0 && entry->nat_ip.nat_ip4 == nat_ipv4)
				|| (nat_ipv6 != NULL && memcmp(nat_ipv6, entry->nat_ip.nat_ip6, sizeof(entry->nat_ip.nat_ip6)) == 0));
}

static __rte_always_inline bool dp_is_network_nat_entry(struct network_nat_entry *entry,
														uint32_t nat_ipv4,
														uint8_t nat_ipv6[DP_VNF_IPV6_ADDR_SIZE], uint32_t vni,
														uint16_t min_port, uint16_t max_port)
{
	return dp_is_network_nat_ip(entry, nat_ipv4, nat_ipv6, vni)
			&& entry->port_range[0] == min_port
			&& entry->port_range[1] == max_port;
}

// check if a port falls into the range of external nat's port range
static __rte_always_inline bool dp_is_network_nat_port(struct network_nat_entry *entry,
													   uint32_t nat_ipv4,
													   uint8_t nat_ipv6[DP_VNF_IPV6_ADDR_SIZE], uint32_t vni,
													   uint16_t port)
{
	return dp_is_network_nat_ip(entry, nat_ipv4, nat_ipv6, vni)
			&& entry->port_range[0] <= port
			&& entry->port_range[1] > port;
}

void dp_del_vip_from_dnat(uint32_t d_ip, uint32_t vni)
{
	network_nat_entry *item;

	// only delete the DNAT entry when this is the only range present for this IP
	// (i.e. if there still is an entry in the list, do nothing!)
	for (item = TAILQ_FIRST(&nat_headp); item != NULL; item = TAILQ_NEXT(item, entries))
		if (dp_is_network_nat_ip(item, d_ip, NULL, vni))
			return;

	dp_del_dnat_ip(d_ip, vni);
}

int dp_add_network_nat_entry(uint32_t nat_ipv4, uint8_t nat_ipv6[DP_VNF_IPV6_ADDR_SIZE],
								uint32_t vni, uint16_t min_port, uint16_t max_port,
								uint8_t ul_ipv6[DP_VNF_IPV6_ADDR_SIZE])
{
	network_nat_entry *next, *new_entry;

	TAILQ_FOREACH(next, &nat_headp, entries) {
		if (dp_is_network_nat_entry(next, nat_ipv4, nat_ipv6, vni, min_port, max_port)) {
			DPS_LOG_ERR("Cannot add a redundant nat entry", DP_LOG_IPV4(nat_ipv4), DP_LOG_VNI(vni),
						DP_LOG_MINPORT(min_port), DP_LOG_MAXPORT(max_port));
			return DP_GRPC_ERR_ALREADY_EXISTS;
		}
	}

	new_entry = (network_nat_entry *)rte_zmalloc("network_nat_array", sizeof(network_nat_entry), RTE_CACHE_LINE_SIZE);
	if (!new_entry) {
		DPS_LOG_ERR("Failed to allocate nat entry", DP_LOG_IPV4(nat_ipv4), DP_LOG_VNI(vni),
					DP_LOG_MINPORT(min_port), DP_LOG_MAXPORT(max_port));
		return DP_GRPC_ERR_OUT_OF_MEMORY;
	}

	if (nat_ipv4)
		new_entry->nat_ip.nat_ip4 = nat_ipv4;

	if (nat_ipv6)
		memcpy(new_entry->nat_ip.nat_ip6, nat_ipv6, sizeof(new_entry->nat_ip.nat_ip6));

	new_entry->vni = vni;
	new_entry->port_range[0] = min_port;
	new_entry->port_range[1] = max_port;
	memcpy(new_entry->dst_ipv6, ul_ipv6, sizeof(new_entry->dst_ipv6));

	TAILQ_INSERT_TAIL(&nat_headp, new_entry, entries);

	return DP_GRPC_OK;

}

int dp_del_network_nat_entry(uint32_t nat_ipv4, uint8_t nat_ipv6[DP_VNF_IPV6_ADDR_SIZE],
								uint32_t vni, uint16_t min_port, uint16_t max_port)
{
	network_nat_entry *item, *tmp_item;

	for (item = TAILQ_FIRST(&nat_headp); item != NULL; item = tmp_item) {
		tmp_item = TAILQ_NEXT(item, entries);
		if (dp_is_network_nat_entry(item, nat_ipv4, nat_ipv6, vni, min_port, max_port)) {
			TAILQ_REMOVE(&nat_headp, item, entries);
			rte_free(item);
			return DP_GRPC_OK;
		}
	}
	return DP_GRPC_ERR_NOT_FOUND;
}

const uint8_t *dp_get_network_nat_underlay_ip(uint32_t nat_ipv4, uint8_t nat_ipv6[DP_VNF_IPV6_ADDR_SIZE],
											  uint32_t vni, uint16_t min_port, uint16_t max_port)
{
	network_nat_entry *current;

	TAILQ_FOREACH(current, &nat_headp, entries) {
		if (dp_is_network_nat_entry(current, nat_ipv4, nat_ipv6, vni, min_port, max_port))
			return current->dst_ipv6;
	}
	return NULL;
}

const uint8_t *dp_lookup_network_nat_underlay_ip(struct dp_flow *df)
{
	struct network_nat_entry *current;
	uint16_t dst_port;
	uint32_t dst_vni;
	uint32_t dst_ip;

	dst_ip = ntohl(df->dst.dst_addr);
	dst_port = ntohs(df->l4_info.trans_port.dst_port);
	dst_vni = df->tun_info.dst_vni;

	TAILQ_FOREACH(current, &nat_headp, entries) {
		if (dp_is_network_nat_port(current, dst_ip, NULL, dst_vni, dst_port))
			return current->dst_ipv6;
	}
	return NULL;
}

int dp_allocate_network_snat_port(struct snat_data *snat_data, struct dp_flow *df, uint32_t vni)
{
	struct netnat_portoverload_tbl_key portoverload_tbl_key;
	struct netnat_portmap_key portmap_key;
	struct netnat_portmap_data *portmap_data;
	uint16_t min_port, max_port, allocated_port = 0, tmp_port;
	uint32_t vm_src_info_hash;
	int ret;
	bool need_to_find_new_port = true;
	uint32_t vm_ip = ntohl(df->src.src_addr);
	uint16_t vm_port = ntohs(df->l4_info.trans_port.src_port);

	portmap_key.vm_src_ip = vm_ip;
	portmap_key.vni = vni;
	portmap_key.vm_src_port = vm_port;

	portoverload_tbl_key.nat_ip = snat_data->network_nat_ip;
	portoverload_tbl_key.dst_ip = ntohl(df->dst.dst_addr);
	portoverload_tbl_key.dst_port = ntohs(df->l4_info.trans_port.dst_port);
	portoverload_tbl_key.l4_type = df->l4_type;

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
		min_port = snat_data->network_nat_port_range[0];
		max_port = snat_data->network_nat_port_range[1];

		vm_src_info_hash = (uint32_t)rte_hash_hash(ipv4_netnat_portmap_tbl, &portmap_key);

		for (uint16_t p = 0; p < max_port - min_port; p++) {
			tmp_port = min_port + (uint16_t)((vm_src_info_hash + p) % (uint32_t)(max_port - min_port));
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
			DPS_LOG_WARNING("No usable ipv4 port found for natting",
							DP_LOG_IPV4(snat_data->network_nat_ip),
							DP_LOG_VNI(vni), DP_LOG_SRC_IPV4(vm_ip),
							DP_LOG_SRC_PORT(vm_port));
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
		portmap_data->nat_ip = snat_data->network_nat_ip;
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

int dp_remove_network_snat_port(struct flow_value *cntrack)
{
	struct netnat_portmap_key portmap_key = {0};
	struct netnat_portoverload_tbl_key portoverload_tbl_key = {0};
	struct netnat_portmap_data *portmap_data;
	int ret;

	portoverload_tbl_key.nat_ip = cntrack->flow_key[DP_FLOW_DIR_REPLY].ip_dst;
	portoverload_tbl_key.nat_port = cntrack->flow_key[DP_FLOW_DIR_REPLY].port_dst;
	portoverload_tbl_key.dst_ip = cntrack->flow_key[DP_FLOW_DIR_ORG].ip_dst;
	portoverload_tbl_key.dst_port = cntrack->flow_key[DP_FLOW_DIR_ORG].port_dst;
	portoverload_tbl_key.l4_type = cntrack->flow_key[DP_FLOW_DIR_ORG].proto;

	ret = rte_hash_lookup(ipv4_netnat_portoverload_tbl, (const void *)&portoverload_tbl_key);
	if (!DP_FAILED(ret)) {
		ret = rte_hash_del_key(ipv4_netnat_portoverload_tbl, &portoverload_tbl_key);
		if (DP_FAILED(ret)) {
			DPS_LOG_ERR("Cannot delete portoverload key", DP_LOG_RET(ret));
			return DP_ERROR;
		}
	} else if (ret != -ENOENT)
		return ret;

	portmap_key.vm_src_ip = cntrack->flow_key[DP_FLOW_DIR_ORG].ip_src;
	portmap_key.vm_src_port = cntrack->flow_key[DP_FLOW_DIR_ORG].src.port_src;
	portmap_key.vni = cntrack->nf_info.vni;

	ret = rte_hash_lookup_data(ipv4_netnat_portmap_tbl, (const void *)&portmap_key, (void **)&portmap_data);

	if (!DP_FAILED(ret)) {
		portmap_data->flow_cnt--;
		if (!portmap_data->flow_cnt) {
			rte_free(portmap_data);
			ret = rte_hash_del_key(ipv4_netnat_portmap_tbl, &portmap_key);
			if (DP_FAILED(ret)) {
				DPS_LOG_ERR("Cannot delete portmap key", DP_LOG_RET(ret));
				return DP_ERROR;
			}
		}
		DP_STATS_NAT_DEC_USED_PORT_CNT(cntrack->created_port_id);
		return DP_OK;
	}
	return ret == -ENOENT ? DP_OK : ret;
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

		if (data->network_nat_ip == nat_ip) {
			reply = dp_grpc_add_reply(responder);
			if (!reply)
				return DP_GRPC_ERR_OUT_OF_MEMORY;
			reply->min_port = data->network_nat_port_range[0];
			reply->max_port = data->network_nat_port_range[1];
			reply->addr.ip_type = RTE_ETHER_TYPE_IPV4;
			reply->addr.ipv4 = nkey->ip;
			reply->vni = nkey->vni;
		}
	}
	return DP_GRPC_OK;
}

int dp_list_nat_neigh_entries(uint32_t nat_ip, struct dp_grpc_responder *responder)
{
	struct network_nat_entry *current;
	struct dpgrpc_nat *reply;

	dp_grpc_set_multireply(responder, sizeof(*reply));

	TAILQ_FOREACH(current, &nat_headp, entries) {
		if (current->nat_ip.nat_ip4 == nat_ip) {
			reply = dp_grpc_add_reply(responder);
			if (!reply)
				return DP_GRPC_ERR_OUT_OF_MEMORY;
			reply->min_port = current->port_range[0];
			reply->max_port = current->port_range[1];
			reply->vni = current->vni;
			rte_memcpy(reply->ul_addr6, current->dst_ipv6, sizeof(current->dst_ipv6));
		}
	}
	return DP_GRPC_OK;
}

void dp_del_all_neigh_nat_entries_in_vni(uint32_t vni)
{
	network_nat_entry *item, *tmp_item;

	for (item = TAILQ_FIRST(&nat_headp); item != NULL; item = tmp_item) {
		tmp_item = TAILQ_NEXT(item, entries);
		if ((item->vni == vni) || (vni == DP_NETWORK_NAT_ALL_VNI)) {
			TAILQ_REMOVE(&nat_headp, item, entries);
			rte_free(item);
		}
	}
}
