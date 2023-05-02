#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_common.h>
#include <rte_errno.h>
#include <rte_malloc.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include "dp_error.h"
#include "node_api.h"
#include "dp_nat.h"
#include "rte_flow/dp_rte_flow.h"
#include "dp_log.h"
#include "dp_internal_stats.h"

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

void dp_nat_free()
{
	dp_free_jhash_table(ipv4_netnat_portoverload_tbl);
	dp_free_jhash_table(ipv4_netnat_portmap_tbl);
	dp_free_jhash_table(ipv4_dnat_tbl);
	dp_free_jhash_table(ipv4_snat_tbl);
}

int dp_check_if_ip_natted(uint32_t vm_ip, uint32_t vni, struct nat_check_result *result)
{
	struct nat_key nkey;
	int ret;
	struct snat_data *data;

	nkey.ip = vm_ip;
	nkey.vni = vni;

	ret = rte_hash_lookup_data(ipv4_snat_tbl, &nkey, (void **)&data);
	if (DP_FAILED(ret)) {
		result->is_vip_natted = false;
		result->is_network_natted = false;
		if (ret == -ENOENT)
			return DP_OK;
		else
			return DP_ERROR;
	}

	if (data->vip_ip == 0)
		result->is_vip_natted = false;
	else
		result->is_vip_natted = true;

	if (data->network_nat_ip == 0)
		result->is_network_natted = false;
	else
		result->is_network_natted = true;

	return DP_OK;

}

uint32_t dp_get_vm_snat_ip(uint32_t vm_ip, uint32_t vni)
{
	struct nat_key nkey;
	struct snat_data *data;

	nkey.ip = vm_ip;
	nkey.vni = vni;

	if (rte_hash_lookup_data(ipv4_snat_tbl, &nkey, (void **)&data) < 0)
		return 0;

	return data->vip_ip;
}

struct snat_data *dp_get_vm_network_snat_data(uint32_t vm_ip, uint32_t vni)
{
	struct snat_data *data;
	struct nat_key nkey;

	nkey.ip = vm_ip;
	nkey.vni = vni;

	if (rte_hash_lookup_data(ipv4_snat_tbl, &nkey, (void **)&data) < 0)
		return NULL;

	return data;
}

uint32_t dp_get_vm_network_snat_ip(uint32_t vm_ip, uint32_t vni)
{
	struct nat_key nkey;
	struct snat_data *data;

	nkey.ip = vm_ip;
	nkey.vni = vni;

	if (rte_hash_lookup_data(ipv4_snat_tbl, &nkey, (void **)&data) < 0)
		return 0;

	return data->network_nat_ip;
}

int dp_set_vm_snat_ip(uint32_t vm_ip, uint32_t s_ip, uint32_t vni, uint8_t *ul_ipv6)
{
	int ret = EXIT_SUCCESS;
	struct nat_key nkey;
	int pos;
	struct snat_data *data;

	nkey.ip = vm_ip;
	nkey.vni = vni;

	if (rte_hash_lookup(ipv4_snat_tbl, &nkey) >= 0) {
		/* Behind the same key, we can have NAT IP and VIP */
		if (rte_hash_lookup_data(ipv4_snat_tbl, &nkey, (void **)&data) < 0) {
			ret = DP_ERROR_VM_ADD_NAT;
			goto err;
		}

		if (data->vip_ip != 0) {
			ret = DP_ERROR_VM_ADD_NAT_IP_EXISTS;
			goto err;
		} else {
			rte_memcpy(data->ul_ip6, ul_ipv6, sizeof(data->ul_ip6));
			data->vip_ip = s_ip;
			return ret;
		}
	}


	if (rte_hash_add_key(ipv4_snat_tbl, &nkey) < 0) {
		ret = DP_ERROR_VM_ADD_NAT_ALLOC;
		goto err;
	}

	data = rte_zmalloc("snat_val", sizeof(struct snat_data), RTE_CACHE_LINE_SIZE);
	if (!data) {
		ret = DP_ERROR_VM_ADD_NAT_ADD_KEY;
		goto err_key;
	}
	rte_memcpy(data->ul_ip6, ul_ipv6, sizeof(data->ul_ip6));
	data->vip_ip = s_ip;
	data->network_nat_ip = 0;

	if (rte_hash_add_key_data(ipv4_snat_tbl, &nkey, data) < 0) {
		ret = DP_ERROR_VM_ADD_NET_NAT_DATA;
		goto out;
	}
	return ret;
out:
	rte_free(data);
err_key:
	pos = rte_hash_del_key(ipv4_snat_tbl, &nkey);
	if (pos < 0)
		DPS_LOG_WARNING("SNAT hash key already deleted");
err:
	DPS_LOG_ERR("snat table add ip failed");
	return ret;
}

int dp_set_vm_network_snat_ip(uint32_t vm_ip, uint32_t s_ip, uint32_t vni, uint16_t min_port,
							  uint16_t max_port, uint8_t *ul_ipv6)
{
	int ret = EXIT_SUCCESS;
	struct nat_key nkey;
	int pos;
	struct snat_data *data;

	nkey.ip = vm_ip;
	nkey.vni = vni;

	if (rte_hash_lookup(ipv4_snat_tbl, &nkey) >= 0) {
		if (rte_hash_lookup_data(ipv4_snat_tbl, &nkey, (void **)&data) < 0) {
			ret = DP_ERROR_VM_ADD_NETNAT_DATA_NOT_FOUND;
			goto err;
		}

		if (data->network_nat_ip != 0) {
			ret = DP_ERROR_VM_ADD_NETNAT_IP_EXISTS;
			goto err;
		} else {
			rte_memcpy(data->ul_nat_ip6, ul_ipv6, sizeof(data->ul_ip6));
			data->network_nat_ip = s_ip;
			data->network_nat_port_range[0] = min_port;
			data->network_nat_port_range[1] = max_port;
			return ret;
		}
	}


	if (rte_hash_add_key(ipv4_snat_tbl, &nkey) < 0) {
		ret = DP_ERROR_VM_ADD_NETNAT_KEY;
		goto err;
	}

	data = rte_zmalloc("snat_val", sizeof(struct snat_data), RTE_CACHE_LINE_SIZE);
	if (!data) {
		ret = DP_ERROR_VM_ADD_NETNAT_ALLO_DATA;
		goto err_key;
	}
	data->network_nat_ip = s_ip;
	data->vip_ip = 0;
	data->network_nat_port_range[0] = min_port;
	data->network_nat_port_range[1] = max_port;
	rte_memcpy(data->ul_nat_ip6, ul_ipv6, sizeof(data->ul_ip6));

	if (rte_hash_add_key_data(ipv4_snat_tbl, &nkey, data) < 0) {
		ret = DP_ERROR_VM_ADD_NETNAT_ADD_DATA;
		goto out;
	}
	return ret;
out:
	rte_free(data);
err_key:
	pos = rte_hash_del_key(ipv4_snat_tbl, &nkey);
	if (pos < 0)
		DPS_LOG_WARNING("SNAT hash key already deleted");
err:
	DPS_LOG_ERR("snat table add ip failed");
	return ret;
}

void dp_del_vm_snat_ip(uint32_t vm_ip, uint32_t vni)
{
	struct nat_key nkey;
	struct snat_data *data;
	int pos;

	nkey.ip = vm_ip;
	nkey.vni = vni;

	if (rte_hash_lookup_data(ipv4_snat_tbl, &nkey, (void **)&data) < 0)
		return;

	if (data->vip_ip)
		data->vip_ip = 0;

	if (data->vip_ip == 0 && data->network_nat_ip == 0) {
		rte_free(data);
		pos = rte_hash_del_key(ipv4_snat_tbl, &nkey);

		if (pos < 0)
			DPS_LOG_WARNING("SNAT hash key already deleted");
	}

}

int dp_del_vm_network_snat_ip(uint32_t vm_ip, uint32_t vni)
{
	struct nat_key nkey;
	struct snat_data *data;
	int pos;


	nkey.ip = vm_ip;
	nkey.vni = vni;

	if (rte_hash_lookup_data(ipv4_snat_tbl, &nkey, (void **)&data) < 0)
		return DP_ERROR_VM_DEL_NETNAT_ENTRY_NOT_FOUND;

	if (data->network_nat_ip) {
		data->network_nat_ip = 0;
		data->network_nat_port_range[0] = 0;
		data->network_nat_port_range[1] = 0;
	}

	if (data->vip_ip == 0 && data->network_nat_ip == 0) {
		rte_free(data);
		pos = rte_hash_del_key(ipv4_snat_tbl, &nkey);

		if (pos < 0) {
			DPS_LOG_WARNING("SNAT hash key already deleted");;
			return DP_ERROR_VM_DEL_NETNAT_KEY_DELETED;
		}
	}

	return EXIT_SUCCESS;

}

bool dp_is_ip_dnatted(uint32_t d_ip, uint32_t vni)
{
	struct nat_key nkey;
	int ret;

	nkey.ip = d_ip;
	nkey.vni = vni;

	ret = rte_hash_lookup(ipv4_dnat_tbl, &nkey);
	if (ret < 0)
		return false;
	return true;
}

uint32_t dp_get_vm_dnat_ip(uint32_t d_ip, uint32_t vni)
{
	struct nat_key nkey;
	uint32_t *dnat_ip;

	nkey.ip = d_ip;
	nkey.vni = vni;

	if (rte_hash_lookup_data(ipv4_dnat_tbl, &nkey, (void **)&dnat_ip) < 0)
		return 0;

	return *dnat_ip;
}

int dp_set_vm_dnat_ip(uint32_t d_ip, uint32_t vm_ip, uint32_t vni)
{
	int ret = EXIT_SUCCESS;
	struct nat_key nkey;
	uint32_t *v_ip;
	int pos;

	nkey.ip = d_ip;
	nkey.vni = vni;

	if (rte_hash_lookup(ipv4_dnat_tbl, &nkey) >= 0) {
		ret = DP_ERROR_VM_ADD_DNAT_IP_EXISTS;
		goto err;
	}

	if (rte_hash_add_key(ipv4_dnat_tbl, &nkey) < 0) {
		ret = DP_ERROR_VM_ADD_DNAT_ALLOC;
		goto err;
	}

	v_ip = rte_zmalloc("dnat_val", sizeof(uint32_t), RTE_CACHE_LINE_SIZE);
	if (!v_ip) {
		ret = DP_ERROR_VM_ADD_DNAT_ADD_KEY;
		goto err_key;
	}

	*v_ip = vm_ip;
	if (rte_hash_add_key_data(ipv4_dnat_tbl, &nkey, v_ip) < 0) {
		ret = DP_ERROR_VM_ADD_DNAT_ADD_KEY;
		goto out;
	}

	return ret;
out:
	rte_free(v_ip);
err_key:
	pos = rte_hash_del_key(ipv4_dnat_tbl, &nkey);
	if (pos < 0)
		DPS_LOG_WARNING("DNAT hash key already deleted");
err:
	return ret;
}

void dp_del_vm_dnat_ip(uint32_t d_ip, uint32_t vni)
{
	struct nat_key nkey;
	uint32_t *vm_ip;
	int pos;

	nkey.ip = d_ip;
	nkey.vni = vni;

	if (rte_hash_lookup_data(ipv4_dnat_tbl, &nkey, (void **)&vm_ip) < 0)
		return;
	rte_free(vm_ip);

	pos = rte_hash_del_key(ipv4_dnat_tbl, &nkey);
	if (pos < 0)
		DPS_LOG_WARNING("DNAT hash key already deleted");
}

void dp_nat_chg_ip(struct dp_flow *df_ptr, struct rte_ipv4_hdr *ipv4_hdr,
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

	switch (df_ptr->l4_type)
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


static int dp_cmp_network_nat_entry(struct network_nat_entry *entry, uint32_t nat_ipv4, uint8_t *nat_ipv6,
								uint32_t vni, uint16_t min_port, uint16_t max_port)
{

	if (((nat_ipv4 != 0 && entry->nat_ip.nat_ip4 == nat_ipv4)
				|| (nat_ipv6 != NULL && memcmp(nat_ipv6, entry->nat_ip.nat_ip6, sizeof(entry->nat_ip.nat_ip6)) == 0))
				&& entry->vni == vni && entry->port_range[0] == min_port && entry->port_range[1] == max_port)
		return 1;
	else
		return 0;
}

// check if a port falls into the range of external nat's port range
static int dp_check_port_network_nat_entry(struct network_nat_entry *entry, uint32_t nat_ipv4, uint8_t *nat_ipv6,
								uint32_t vni, uint16_t port)
{
	if (((nat_ipv4 != 0 && entry->nat_ip.nat_ip4 == nat_ipv4)
				|| (nat_ipv6 != NULL && memcmp(nat_ipv6, entry->nat_ip.nat_ip6, sizeof(entry->nat_ip.nat_ip6)) == 0))
				&& entry->vni == vni && entry->port_range[0] <= port && entry->port_range[1] > port)
		return 1;

	else
		return 0;

}

int dp_add_network_nat_entry(uint32_t nat_ipv4, uint8_t *nat_ipv6,
								uint32_t vni, uint16_t min_port, uint16_t max_port,
								uint8_t *underlay_ipv6)
{

	network_nat_entry *next, *new_entry;

	TAILQ_FOREACH(next, &nat_headp, entries) {
		if (dp_cmp_network_nat_entry(next, nat_ipv4, nat_ipv6, vni, min_port, max_port)) {
			DPS_LOG_ERR("cannot add a redundant network nat entry for ip: %4x, vni: %d, min_port %d, max_port %d",
					nat_ipv4, vni, min_port, max_port);
			return DP_ERROR_VM_ADD_NEIGHNAT_ENTRY_EXIST;
		}
	}

	new_entry = (network_nat_entry *)rte_zmalloc("network_nat_array", sizeof(network_nat_entry), RTE_CACHE_LINE_SIZE);

	if (!new_entry) {
		DPS_LOG_ERR("failed to allocate network nat entry for ip: %4x, vni: %d", nat_ipv4, vni);
		return DP_ERROR_VM_ADD_NEIGHNAT_ALLOC;
	}

	if (nat_ipv4)
		new_entry->nat_ip.nat_ip4 = nat_ipv4;

	if (nat_ipv6)
		memcpy(new_entry->nat_ip.nat_ip6, nat_ipv6, sizeof(new_entry->nat_ip.nat_ip6));

	new_entry->vni = vni;
	new_entry->port_range[0] = min_port;
	new_entry->port_range[1] = max_port;
	memcpy(new_entry->dst_ipv6, underlay_ipv6, sizeof(new_entry->dst_ipv6));

	TAILQ_INSERT_TAIL(&nat_headp, new_entry, entries);

	return EXIT_SUCCESS;

}

int dp_del_network_nat_entry(uint32_t nat_ipv4, uint8_t *nat_ipv6,
								uint32_t vni, uint16_t min_port, uint16_t max_port)
{
	network_nat_entry *item, *tmp_item;

	for (item = TAILQ_FIRST(&nat_headp); item != NULL; item = tmp_item) {
		tmp_item = TAILQ_NEXT(item, entries);
		if (dp_cmp_network_nat_entry(item, nat_ipv4, nat_ipv6, vni, min_port, max_port)) {
			TAILQ_REMOVE(&nat_headp, item, entries);
			rte_free(item);
			return EXIT_SUCCESS;
		}
	}

	return DP_ERROR_VM_DEL_NEIGHNAT_ENTRY_NOFOUND;
}

const uint8_t *dp_get_network_nat_underlay_ip(uint32_t nat_ipv4, uint8_t *nat_ipv6,
											  uint32_t vni, uint16_t min_port, uint16_t max_port)
{
	network_nat_entry *current;

	TAILQ_FOREACH(current, &nat_headp, entries) {
		if (dp_cmp_network_nat_entry(current, nat_ipv4, nat_ipv6, vni, min_port, max_port))
			return current->dst_ipv6;
	}
	return NULL;
}

const uint8_t *dp_lookup_network_nat_underlay_ip(struct dp_flow *df_ptr)
{
	struct network_nat_entry *current;
	uint16_t dst_port;
	uint32_t dst_vni;
	uint32_t dst_ip;

	dst_ip = ntohl(df_ptr->dst.dst_addr);
	dst_port = ntohs(df_ptr->l4_info.trans_port.dst_port);
	dst_vni = df_ptr->tun_info.dst_vni;

	TAILQ_FOREACH(current, &nat_headp, entries) {
		if (dp_check_port_network_nat_entry(current, dst_ip, NULL, dst_vni, dst_port))
			return current->dst_ipv6;
	}
	return NULL;
}

int dp_allocate_network_snat_port(struct dp_flow *df_ptr, uint32_t vni)
{
	struct nat_key nkey = {0};
	struct snat_data *data;
	struct netnat_portoverload_tbl_key portoverload_tbl_key = {0};
	struct netnat_portmap_key portmap_key = {0};
	struct netnat_portmap_data *portmap_data;
	uint16_t min_port, max_port, allocated_port = 0, tmp_port = 0;
	uint32_t vm_src_info_hash;
	int ret;
	bool need_to_find_new_port = true;

	uint32_t vm_ip = ntohl(df_ptr->src.src_addr);
	uint16_t vm_port = ntohs(df_ptr->l4_info.trans_port.src_port);

	nkey.ip = vm_ip;
	nkey.vni = vni;

	ret = rte_hash_lookup_data(ipv4_snat_tbl, &nkey, (void **)&data);
	if (DP_FAILED(ret)) {
		DPS_LOG_ERR("Cannot lookup ipv4 snat key %s", dp_strerror(ret));
		return ret;
	}

	if (data->network_nat_ip == 0) {
		DPS_LOG_ERR("Snat ipv4 lookup data invalid");
		return DP_ERROR;
	}

	portmap_key.vm_src_ip = vm_ip;
	portmap_key.vni = vni;
	portmap_key.vm_src_port = vm_port;

	portoverload_tbl_key.nat_ip = data->network_nat_ip;
	portoverload_tbl_key.dst_ip = ntohl(df_ptr->dst.dst_addr);
	portoverload_tbl_key.dst_port = ntohs(df_ptr->l4_info.trans_port.dst_port);
	portoverload_tbl_key.l4_type = df_ptr->l4_type;

	ret = rte_hash_lookup_data(ipv4_netnat_portmap_tbl, &portmap_key, (void **)&portmap_data);
	if (ret != -ENOENT) {
		if (DP_FAILED(ret)) {
			DPS_LOG_ERR("Cannot lookup ipv4 portmap key %s", dp_strerror(ret));
			return ret;
		}

		portoverload_tbl_key.nat_port = portmap_data->nat_port;
		ret = rte_hash_lookup(ipv4_netnat_portoverload_tbl, &portoverload_tbl_key);

		if (likely(ret == -ENOENT)) {
			portmap_data->flow_cnt++;
			allocated_port = portmap_data->nat_port;
			need_to_find_new_port = false;
		} else if (DP_FAILED(ret)) {
			DPS_LOG_ERR("Cannot lookup ipv4 port overload key for an existing nat port  %s", dp_strerror(ret));
			return ret;
		}
	}

	if (need_to_find_new_port) {
		min_port = data->network_nat_port_range[0];
		max_port = data->network_nat_port_range[1];

		vm_src_info_hash = (uint32_t)rte_hash_hash(ipv4_netnat_portmap_tbl, &portmap_key);

		for (uint16_t p = 0; p < max_port - min_port; p++) {
			tmp_port = min_port + (uint16_t)((vm_src_info_hash + p) % (uint32_t)(max_port - min_port));
			portoverload_tbl_key.nat_port = tmp_port;
			ret = rte_hash_lookup(ipv4_netnat_portoverload_tbl, &portoverload_tbl_key);
			if (ret == -ENOENT) {
				allocated_port = tmp_port;
				break;
			} else if (DP_FAILED(ret)) {
				DPS_LOG_ERR("Cannot lookup ipv4 port overload key %s", dp_strerror(ret));
				return ret;
			}
		}

		if (!allocated_port) {
			DPS_LOG_ERR("No usable ipv4 port found for natting");
			return DP_ERROR;
		}

	}

	ret = rte_hash_add_key(ipv4_netnat_portoverload_tbl, (const void *)&portoverload_tbl_key);
	if (DP_FAILED(ret)) {
		DPS_LOG_ERR("Failed to add ipv4 network nat port overload key %s", dp_strerror(ret));
		return ret;
	}

	if (need_to_find_new_port) {
		portmap_data = rte_zmalloc("netnat_portmap_val", sizeof(struct netnat_portmap_data), RTE_CACHE_LINE_SIZE);
		portmap_data->nat_ip = data->network_nat_ip;
		portmap_data->nat_port = allocated_port;
		portmap_data->flow_cnt++;

		ret = rte_hash_add_key_data(ipv4_netnat_portmap_tbl, (const void *)&portmap_key, (void *)portmap_data);
		if (DP_FAILED(ret)) {
			rte_free(portmap_data);
			DPS_LOG_ERR("Failed to add ipv4 network nat portmap data %s", dp_strerror(ret));
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
	int ret = 0;

	portoverload_tbl_key.nat_ip = cntrack->flow_key[DP_FLOW_DIR_REPLY].ip_dst;
	portoverload_tbl_key.nat_port = cntrack->flow_key[DP_FLOW_DIR_REPLY].port_dst;
	portoverload_tbl_key.dst_ip = cntrack->flow_key[DP_FLOW_DIR_ORG].ip_dst;
	portoverload_tbl_key.dst_port = cntrack->flow_key[DP_FLOW_DIR_ORG].port_dst;
	portoverload_tbl_key.l4_type = cntrack->flow_key[DP_FLOW_DIR_ORG].proto;

	ret = rte_hash_lookup(ipv4_netnat_portoverload_tbl, (const void *)&portoverload_tbl_key);
	if (!DP_FAILED(ret)) {
		if (DP_FAILED(rte_hash_del_key(ipv4_netnat_portoverload_tbl, &portoverload_tbl_key)))
				return DP_ERROR;
	} else if (ret == -EINVAL)
		return DP_ERROR;

	portmap_key.vm_src_ip = cntrack->flow_key[DP_FLOW_DIR_ORG].ip_src;
	portmap_key.vm_src_port = cntrack->flow_key[DP_FLOW_DIR_ORG].src.port_src;
	portmap_key.vni = cntrack->nat_info.vni;

	ret = rte_hash_lookup_data(ipv4_netnat_portmap_tbl, (const void *)&portmap_key, (void **)&portmap_data);

	if (!DP_FAILED(ret)) {
		portmap_data->flow_cnt--;
		if (!portmap_data->flow_cnt) {
			rte_free(portmap_data);
			if (DP_FAILED(rte_hash_del_key(ipv4_netnat_portmap_tbl, &portmap_key)))
				return DP_ERROR;
		}
		DP_STATS_NAT_DEC_USED_PORT_CNT(cntrack->created_port_id);
		return DP_OK;
	} else if (ret == -ENOENT)
		return DP_OK;
	else
		return DP_ERROR;
}

int dp_list_nat_local_entry(struct rte_mbuf *m, struct rte_mbuf *rep_arr[], uint32_t nat_ip)
{
	int8_t rep_arr_size = DP_MBUF_ARR_SIZE;
	struct rte_mbuf *m_new, *m_curr = m;
	uint16_t msg_per_buf;
	struct nat_key *nkey;
	struct snat_data *data;
	dp_reply *rep;
	uint32_t index = 0;
	int32_t ret;
	struct dp_nat_entry *rp_nat_entry;

	if (rte_hash_count(ipv4_snat_tbl) == 0)
		goto err;

	msg_per_buf = dp_first_mbuf_to_grpc_arr(m_curr, rep_arr,
										    &rep_arr_size, sizeof(struct dp_nat_entry));
	rep = rte_pktmbuf_mtod(m_curr, dp_reply*);

	while (true) {
		ret = rte_hash_iterate(ipv4_snat_tbl, (const void **)&nkey, (void **)&data, &index);
		if (ret == -EINVAL)
			return DP_ERROR_VM_GET_NETNAT_ITER_ERROR;

		if (ret == -ENOENT)
			break; // no more key-data item, thus break / return

		if (data->network_nat_ip == nat_ip) {
			if (rep->com_head.msg_count &&
				(rep->com_head.msg_count % msg_per_buf == 0)) {

				m_new = dp_add_mbuf_to_grpc_arr(m_curr, rep_arr, &rep_arr_size);
				if (!m_new)
					break;
				m_curr = m_new;
				rep = rte_pktmbuf_mtod(m_new, dp_reply*);
			}
			rp_nat_entry = &((&rep->nat_entry)[rep->com_head.msg_count % msg_per_buf]);
			rep->com_head.msg_count++;

			rp_nat_entry->entry_type = DP_NETNAT_INFO_TYPE_LOCAL;
			rp_nat_entry->min_port = data->network_nat_port_range[0];
			rp_nat_entry->max_port = data->network_nat_port_range[1];
			rp_nat_entry->m_ip.addr = nkey->ip;
		}
	}

	if (rep_arr_size < 0) {
		dp_last_mbuf_from_grpc_arr(m_curr, rep_arr);
		return EXIT_SUCCESS;
	}

err:
	rep_arr[--rep_arr_size] = m_curr;

	return EXIT_SUCCESS;
}

int dp_list_nat_neigh_entry(struct rte_mbuf *m, struct rte_mbuf *rep_arr[], uint32_t nat_ip)
{
	int8_t rep_arr_size = DP_MBUF_ARR_SIZE;
	struct rte_mbuf *m_new, *m_curr = m;
	struct dp_nat_entry *rp_nat_entry;
	struct network_nat_entry *current ;
	uint16_t msg_per_buf;
	dp_reply *rep;

	msg_per_buf = dp_first_mbuf_to_grpc_arr(m_curr, rep_arr,
										    &rep_arr_size, sizeof(struct dp_nat_entry));
	rep = rte_pktmbuf_mtod(m_curr, dp_reply*);

	TAILQ_FOREACH(current, &nat_headp, entries) {
		if (current->nat_ip.nat_ip4 == nat_ip) {
			if (rep->com_head.msg_count &&
				(rep->com_head.msg_count % msg_per_buf == 0)) {
					m_new = dp_add_mbuf_to_grpc_arr(m_curr, rep_arr, &rep_arr_size);
					if (!m_new)
						break;
					m_curr = m_new;
					rep = rte_pktmbuf_mtod(m_new, dp_reply*);
			}
			rp_nat_entry = &((&rep->nat_entry)[rep->com_head.msg_count % msg_per_buf]);
			rep->com_head.msg_count++;
			rp_nat_entry->entry_type = DP_NETNAT_INFO_TYPE_NEIGHBOR;
			rp_nat_entry->min_port = current->port_range[0];
			rp_nat_entry->max_port = current->port_range[1];
			rte_memcpy(rp_nat_entry->underlay_route, current->dst_ipv6, sizeof(current->dst_ipv6));
		}
	}

	if (rep_arr_size < 0) {
		dp_last_mbuf_from_grpc_arr(m_curr, rep_arr);
		return EXIT_SUCCESS;
	}

	rep_arr[--rep_arr_size] = m_curr;

	return EXIT_SUCCESS;
}
