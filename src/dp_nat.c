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

static struct rte_hash *ipv4_dnat_tbl = NULL;
static struct rte_hash *ipv4_snat_tbl = NULL;

void dp_init_nat_tables(int socket_id)
{
	struct rte_hash_parameters ipv4_nat_table_params = {
		.name = NULL,
		.entries = DP_NAT_TABLE_MAX,
		.key_len =  sizeof(struct nat_key),
		.hash_func = rte_jhash,
		.hash_func_init_val = 0xfee1900d,
		.extra_flag = 0,
	};
	char s[64];

	snprintf(s, sizeof(s), "ipv4_snat_table_%u", socket_id);
	ipv4_nat_table_params.name = s;
	ipv4_nat_table_params.socket_id = socket_id;
	ipv4_snat_tbl = rte_hash_create(&ipv4_nat_table_params);
	if(!ipv4_snat_tbl)
		rte_exit(EXIT_FAILURE, "create ipv4 snat table failed\n");

	snprintf(s, sizeof(s), "ipv4_dnat_table_%u", socket_id);
	ipv4_nat_table_params.name = s;
	ipv4_nat_table_params.socket_id = socket_id;
	ipv4_dnat_tbl = rte_hash_create(&ipv4_nat_table_params);
	if(!ipv4_dnat_tbl)
		rte_exit(EXIT_FAILURE, "create ipv4 dnat table failed\n");
}

bool dp_is_ip_snatted(uint32_t vm_ip, uint32_t vni)
{
	struct nat_key nkey;
	int ret;

	nkey.ip = vm_ip;
	nkey.vni = vni;

	ret = rte_hash_lookup(ipv4_snat_tbl, &nkey);
	if (ret < 0)
		return false;
	return true;
}

uint32_t dp_get_vm_snat_ip(uint32_t vm_ip, uint32_t vni)
{
	struct nat_key nkey;
	uint32_t *snat_ip;

	nkey.ip = vm_ip;
	nkey.vni = vni;

	if (rte_hash_lookup_data(ipv4_snat_tbl, &nkey, (void**)&snat_ip) < 0)
		return 0;

	return *snat_ip;
}

int dp_set_vm_snat_ip(uint32_t vm_ip, uint32_t s_ip, uint32_t vni)
{
	int ret = EXIT_SUCCESS;
	struct nat_key nkey;
	uint32_t *snat_ip;
	int pos;

	nkey.ip = vm_ip;
	nkey.vni = vni;

	if (rte_hash_lookup(ipv4_snat_tbl, &nkey) >= 0) {
		ret = DP_ERROR_VM_ADD_NAT_IP_EXISTS;
		goto err;
	}

	if (rte_hash_add_key(ipv4_snat_tbl, &nkey) < 0) {
		ret = DP_ERROR_VM_ADD_NAT_ALLOC;
		goto err;
	}

	snat_ip = rte_zmalloc("snat_val", sizeof(uint32_t), RTE_CACHE_LINE_SIZE);
	if (!snat_ip) {
		ret = DP_ERROR_VM_ADD_NAT_ADD_KEY;
		goto err_key;
	}

	*snat_ip = s_ip;
	if (rte_hash_add_key_data(ipv4_snat_tbl, &nkey, snat_ip) < 0) {
		ret = DP_ERROR_VM_ADD_NAT_ADD_DATA;
		goto out;
	}

	return ret;
out:
	rte_free(snat_ip);
err_key:
	pos = rte_hash_del_key(ipv4_snat_tbl, &nkey);
	if (pos < 0)
		printf("SNAT hash key already deleted \n");
	else
		rte_hash_free_key_with_position(ipv4_snat_tbl, pos);
err:
	printf("snat table add ip failed\n");
	return ret;
}

void dp_del_vm_snat_ip(uint32_t vm_ip, uint32_t vni)
{
	struct nat_key nkey;
	uint32_t *snat_ip;
	int pos;

	nkey.ip = vm_ip;
	nkey.vni = vni;

	if (rte_hash_lookup_data(ipv4_snat_tbl, &nkey, (void**)&snat_ip) < 0)
		return;
	rte_free(snat_ip);

	pos = rte_hash_del_key(ipv4_snat_tbl, &nkey);
	if (pos < 0)
		printf("SNAT hash key already deleted \n");
	else
		rte_hash_free_key_with_position(ipv4_snat_tbl, pos);
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

	if (rte_hash_lookup_data(ipv4_dnat_tbl, &nkey, (void**)&dnat_ip) < 0)
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
		printf("DNAT hash key already deleted \n");
	else
		rte_hash_free_key_with_position(ipv4_dnat_tbl, pos);
err:
	printf("dnat table add ip failed\n");
	return ret;
}

void dp_del_vm_dnat_ip(uint32_t d_ip, uint32_t vni)
{
	struct nat_key nkey;
	uint32_t *vm_ip;
	int pos;

	nkey.ip = d_ip;
	nkey.vni = vni;

	if (rte_hash_lookup_data(ipv4_dnat_tbl, &nkey, (void**)&vm_ip) < 0)
		return;
	rte_free(vm_ip);

	pos = rte_hash_del_key(ipv4_dnat_tbl, &nkey);
	if (pos < 0)
		printf("DNAT hash key already deleted \n");
	else
		rte_hash_free_key_with_position(ipv4_dnat_tbl, pos);
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
			m->l4_len = (tcp_hdr->data_off & 0xf0) >> 2;
		break;
		case IPPROTO_UDP:
			udp_hdr =  (struct rte_udp_hdr *)(ipv4_hdr + 1);
			udp_hdr->dgram_cksum = 0;
			m->ol_flags |= RTE_MBUF_F_TX_UDP_CKSUM;
			m->l4_len = sizeof(struct rte_udp_hdr);
		break;
		case IPPROTO_ICMP:
		break;
		default:
		break;
	}
}