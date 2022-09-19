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

static struct rte_hash *ipv4_dnat_tbl = NULL;
static struct rte_hash *ipv4_snat_tbl = NULL;

static struct rte_hash *ipv4_network_dnat_tbl = NULL;
static struct horizontal_nat_entry *network_nat_db = NULL;

// test code
// static uint32_t dp_vm_ip4 = RTE_IPV4(176, 44, 33, 12);
// static uint32_t dp_vm_hrzt_ip4 = RTE_IPV4(45, 66, 77, 88);
// static uint32_t dp_vm_hrzt_extern_ip4 = RTE_IPV4(45, 88, 77, 66);
// static uint8_t dp_underlay_ip6[16] = {0x2a, 0x10, 0xaf, 0xc0, 0xe0, 0x1f, 0xf4, 0x04, 0, 0, 0, 0x64, 0, 0, 0, 0};

// static void hrzt_nat_init()
// {
// 	int ret;
// 	ret = dp_set_vm_hrztl_snat_ip(dp_vm_ip4,dp_vm_hrzt_ip4,100,1000,1200);
// 	printf("Add hrzt nat svip result is %d\n",ret);

// 	ret = dp_add_horizontal_nat_entry(dp_vm_hrzt_extern_ip4, NULL, 
// 								100, 2000,2500,
// 								dp_underlay_ip6);
	
// 	printf("Add hrzt nat extern entry result is %d\n",ret);

// }


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

	struct rte_hash_parameters ipv4_network_dnat_table_params = {
		.name = NULL,
		.entries = DP_NAT_TABLE_MAX,
		.key_len =  sizeof(struct network_dnat_key),
		.hash_func = rte_jhash,
		.hash_func_init_val = 0xfee1900e,
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


	snprintf(s, sizeof(s), "ipv4_network_dnat_table_%u", socket_id);
	ipv4_network_dnat_table_params.name = s;
	ipv4_network_dnat_table_params.socket_id = socket_id;
	ipv4_network_dnat_tbl = rte_hash_create(&ipv4_network_dnat_table_params);
	if(!ipv4_network_dnat_tbl)
		rte_exit(EXIT_FAILURE, "create ipv4 network dnat table failed\n");	

	//  hrzt_nat_init();
}

bool dp_is_ip_snatted(uint32_t vm_ip, uint32_t vni)
{
	struct nat_key nkey;
	int ret;
	struct snat_data *data;

	nkey.ip = vm_ip;
	nkey.vni = vni;

	ret = rte_hash_lookup(ipv4_snat_tbl, &nkey);
	if (ret < 0)
		return false;

	if (rte_hash_lookup_data(ipv4_snat_tbl, &nkey, (void**)&data) < 0)
		return false;

	if (data->vip_ip == 0)
		return false;

	return true;
}

bool dp_is_ip_hrztl_snatted(uint32_t vm_ip, uint32_t vni)
{
	struct nat_key nkey;
	int ret;
	struct snat_data *data;

	nkey.ip = vm_ip;
	nkey.vni = vni;

	printf("not 0\n");
	ret = rte_hash_lookup(ipv4_snat_tbl, &nkey);
	if (ret < 0){
		printf("not found the key\n");
		return false;
	}
	printf("not 1\n");
	if (rte_hash_lookup_data(ipv4_snat_tbl, &nkey, (void**)&data) < 0)
		return false;
	printf("not 2\n");
	if (data->horizontal_nat_ip == 0)
		return false;

	return true;
}

uint32_t dp_get_vm_snat_ip(uint32_t vm_ip, uint32_t vni)
{
	struct nat_key nkey;
	// uint32_t snat_ip;

	struct snat_data *data;

	nkey.ip = vm_ip;
	nkey.vni = vni;

	if (rte_hash_lookup_data(ipv4_snat_tbl, &nkey, (void**)&data) < 0)
		return 0;

	// snat_ip=data->vip_ip;

	// return snat_ip;
	return data->vip_ip;
}

uint32_t dp_get_vm_hrztl_snat_ip(uint32_t vm_ip, uint32_t vni)
{
	struct nat_key nkey;
	// uint32_t *snat_ip;

	struct snat_data *data;

	nkey.ip = vm_ip;
	nkey.vni = vni;

	if (rte_hash_lookup_data(ipv4_snat_tbl, &nkey, (void**)&data) < 0)
		return 0;

	// *snat_ip=data->horizontal_nat_ip;

	// return *snat_ip;
	return data->horizontal_nat_ip;
}

int dp_set_vm_snat_ip(uint32_t vm_ip, uint32_t s_ip, uint32_t vni)
{
	int ret = EXIT_SUCCESS;
	struct nat_key nkey;
	// uint32_t *snat_ip;
	int pos;
	struct snat_data *data;

	nkey.ip = vm_ip;
	nkey.vni = vni;

	if (rte_hash_lookup(ipv4_snat_tbl, &nkey) >= 0) {
		if (rte_hash_lookup_data(ipv4_snat_tbl, &nkey, (void**)&data) < 0){
			ret = DP_REQ_TYPE_ADD_NATVIP;
			goto err;
		}

		if (data->vip_ip != 0){
			ret = DP_ERROR_VM_ADD_NAT_IP_EXISTS;
			goto err;
		}else{
			data->vip_ip=s_ip;
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
	data->vip_ip=s_ip;

	if (rte_hash_add_key_data(ipv4_snat_tbl, &nkey, data) < 0) {
		ret = DP_ERROR_VM_ADD_NET_NAT_DATA;
		goto out;
	}

	// snat_ip = rte_zmalloc("snat_val", sizeof(uint32_t), RTE_CACHE_LINE_SIZE);
	// if (!snat_ip) {
	// 	ret = DP_ERROR_VM_ADD_NAT_ADD_KEY;
	// 	goto err_key;
	// }

	// snat_ip = s_ip;
	// if (rte_hash_add_key_data(ipv4_snat_tbl, &nkey, snat_ip) < 0) {
	// 	ret = DP_ERROR_VM_ADD_NAT_ADD_DATA;
	// 	goto out;
	// }

	return ret;
out:
	rte_free(data);
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

int dp_set_vm_hrztl_snat_ip(uint32_t vm_ip, uint32_t s_ip, uint32_t vni, uint16_t min_port, uint16_t max_port)
{
	int ret = EXIT_SUCCESS;
	struct nat_key nkey;
	// uint32_t *snat_ip;
	int pos;
	struct snat_data *data;

	nkey.ip = vm_ip;
	nkey.vni = vni;

	printf("add to nat vip table: %d, %d, %d, %d, %d \n", vm_ip, s_ip, vni, min_port, max_port);

	if (rte_hash_lookup(ipv4_snat_tbl, &nkey) >= 0) {
		if (rte_hash_lookup_data(ipv4_snat_tbl, &nkey, (void**)&data) < 0){
			ret = DP_ERROR_VM_ADD_NETNAT_DATA_NOT_FOUND;
			goto err;
		}

		if (data->horizontal_nat_ip != 0){
			ret = DP_ERROR_VM_ADD_NAT_IP_EXISTS;
			goto err;
		}else{
			data->horizontal_nat_ip=s_ip;
			data->horizontal_nat_port_range[0]=min_port;
			data->horizontal_nat_port_range[1]=max_port;
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
	printf("add hrzl nat \n");
	data->horizontal_nat_ip=s_ip;
	data->horizontal_nat_port_range[0]=min_port;
	data->horizontal_nat_port_range[1]=max_port;

	if (rte_hash_add_key_data(ipv4_snat_tbl, &nkey, data) < 0) {
		ret = DP_ERROR_VM_ADD_NET_NAT_DATA;
		goto out;
	}

	// snat_ip = rte_zmalloc("snat_val", sizeof(uint32_t), RTE_CACHE_LINE_SIZE);
	// if (!snat_ip) {
	// 	ret = DP_ERROR_VM_ADD_NAT_ADD_KEY;
	// 	goto err_key;
	// }

	// snat_ip = s_ip;
	// if (rte_hash_add_key_data(ipv4_snat_tbl, &nkey, snat_ip) < 0) {
	// 	ret = DP_ERROR_VM_ADD_NAT_ADD_DATA;
	// 	goto out;
	// }

	return ret;
out:
	rte_free(data);
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
	// uint32_t *snat_ip;
	struct snat_data *data;
	int pos;

	nkey.ip = vm_ip;
	nkey.vni = vni;

	if (rte_hash_lookup_data(ipv4_snat_tbl, &nkey, (void**)&data) < 0)
		return;

	if (data->vip_ip)
		data->vip_ip = 0;

	if (data->vip_ip == 0 && data->horizontal_nat_ip ==0){
		rte_free(data);
		pos = rte_hash_del_key(ipv4_snat_tbl, &nkey);

		if (pos < 0)
			printf("SNAT hash key already deleted \n");
		else
			rte_hash_free_key_with_position(ipv4_snat_tbl, pos);
	}

}

int dp_del_vm_hrztl_snat_ip(uint32_t vm_ip, uint32_t vni)
{
	struct nat_key nkey;
	// uint32_t *snat_ip;
	struct snat_data *data;
	int pos;
	

	nkey.ip = vm_ip;
	nkey.vni = vni;

	printf("del from nat vip table: %d, %d\n", vm_ip, vni);

	if (rte_hash_lookup_data(ipv4_snat_tbl, &nkey, (void**)&data) < 0)
		return DP_ERROR_VM_DEL_NETNAT_ENTRY_NOT_FOUND;

	if (data->horizontal_nat_ip){
		data->horizontal_nat_ip = 0;
		data->horizontal_nat_port_range[0]=0;
		data->horizontal_nat_port_range[1]=0;
	}

	if (data->vip_ip == 0 && data->horizontal_nat_ip ==0){
		rte_free(data);
		pos = rte_hash_del_key(ipv4_snat_tbl, &nkey);

		if (pos < 0){
			printf("SNAT hash key already deleted \n");
			return EXIT_FAILURE;
		}
		else
			rte_hash_free_key_with_position(ipv4_snat_tbl, pos);
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
			m->l4_len = sizeof(struct rte_icmp_hdr);
		break;
		default:
		break;
	}
}


static int dp_cmp_horizontal_nat_entry(struct horizontal_nat_entry *entry, uint32_t nat_ipv4, uint8_t *nat_ipv6, 
								uint32_t vni, uint16_t min_port, uint16_t max_port)
{

	if(((nat_ipv4 != 0 && entry->nat_ip.nat_ip4 == nat_ipv4)
				|| (nat_ipv6 != NULL && memcmp(nat_ipv6,entry->nat_ip.nat_ip6,sizeof(entry->nat_ip.nat_ip6)) == 0))
				&& entry->vni == vni && entry->port_range[0] == min_port && entry->port_range[1] == max_port)
		return 1;

	else
		return 0;
}

// check if a port falls into the range of external nat's port range
static int dp_check_port_network_nat_entry(struct horizontal_nat_entry *entry, uint32_t nat_ipv4, uint8_t *nat_ipv6, 
								uint32_t vni, uint16_t port)
{
	if(((nat_ipv4 != 0 && entry->nat_ip.nat_ip4 == nat_ipv4)
				|| (nat_ipv6 != NULL && memcmp(nat_ipv6,entry->nat_ip.nat_ip6,sizeof(entry->nat_ip.nat_ip6)) == 0))
				&& entry->vni == vni && entry->port_range[0] <= port && entry->port_range[1] >= port)
		return 1;

	else
		return 0;

}

int dp_add_horizontal_nat_entry(uint32_t nat_ipv4, uint8_t *nat_ipv6, 
								uint32_t vni, uint16_t min_port, uint16_t max_port,
								uint8_t *underlay_ipv6)
{

	struct horizontal_nat_entry *last;

	printf("try to add neigh nat: %d, %d, %d, %d,%x, %x \n",nat_ipv4, vni, min_port,max_port,underlay_ipv6[14],underlay_ipv6[15]);
	if (network_nat_db!=NULL){
		last = network_nat_db;
		while (last->next != NULL){
			int is_entry_found = dp_cmp_horizontal_nat_entry(last,nat_ipv4,nat_ipv6,vni,min_port,max_port);
			if (!is_entry_found){
					printf("cannot add a redundant horizontal nat entry for ip: %4x, vni: %d \n", nat_ipv4, vni);
					return EXIT_FAILURE;
				}
		}
	}

	struct horizontal_nat_entry *new_entry = (struct horizontal_nat_entry *)rte_zmalloc("horizontal_nat_array",sizeof(struct horizontal_nat_entry),RTE_CACHE_LINE_SIZE);
	if (!new_entry){
		printf("failed to allocate horizontal nat entry for ip: %4x, vni: %d \n", nat_ipv4, vni);
		return EXIT_FAILURE;
	}

	if (nat_ipv4 != 0)
		new_entry->nat_ip.nat_ip4=nat_ipv4;
	
	if (nat_ipv6!=NULL)
		memcpy(new_entry->nat_ip.nat_ip6, nat_ipv6, sizeof(new_entry->nat_ip.nat_ip6));
	
	new_entry->vni = vni;
	new_entry->port_range[0]=min_port;
	new_entry->port_range[1]=max_port;
	memcpy(new_entry->dst_ipv6,underlay_ipv6,sizeof(new_entry->dst_ipv6));
	new_entry->next=NULL;

	if(network_nat_db==NULL){
		network_nat_db=new_entry;
		return EXIT_SUCCESS;
	}

	last->next=new_entry;
	return EXIT_SUCCESS;

}

int dp_del_horizontal_nat_entry(uint32_t nat_ipv4, uint8_t *nat_ipv6, 
								uint32_t vni,uint16_t min_port, uint16_t max_port)
{
	struct horizontal_nat_entry *tmp = network_nat_db, *prev;
	int is_nat_entry_found=0;

	printf("try to del neigh nat: %d, %d, %d, %d, \n",nat_ipv4, vni, min_port,max_port);
	is_nat_entry_found=dp_cmp_horizontal_nat_entry(tmp,nat_ipv4,nat_ipv6,vni,min_port,max_port);
	if (tmp!=NULL && is_nat_entry_found) {
		network_nat_db=tmp->next;
		printf("free the first element\n");
		if (tmp == NULL)
			printf("tmp is null here\n");
		rte_free(tmp);
		return EXIT_SUCCESS;
	}
	printf("continue to find ...\n");
	while (tmp!=NULL && !is_nat_entry_found){
		prev = tmp;
		tmp=tmp->next;
		is_nat_entry_found = dp_cmp_horizontal_nat_entry(tmp,nat_ipv4,nat_ipv6,vni,min_port,max_port);
	}

	if (tmp==NULL)
		return EXIT_FAILURE;

	prev->next=tmp->next;
	rte_free(tmp);
	return EXIT_SUCCESS;

}

int dp_get_horizontal_nat_underlay_ip(uint32_t nat_ipv4, uint8_t *nat_ipv6, 
								uint32_t vni,uint16_t min_port, uint16_t max_port, uint8_t *underlay_ipv6)
{

	struct horizontal_nat_entry *current = network_nat_db;

	while (current!=NULL){
		int is_nat_entry_found = dp_cmp_horizontal_nat_entry(current,nat_ipv4,nat_ipv6,vni,min_port,max_port);
		if (is_nat_entry_found){
			memcpy(underlay_ipv6,current->dst_ipv6,sizeof(current->dst_ipv6));
			return EXIT_SUCCESS;
		}
		current = current->next;
	}

	return EXIT_FAILURE;
}

int dp_lookup_horizontal_nat_underlay_ip(struct rte_mbuf *pkt, uint8_t *underlay_ipv6)
{
	struct dp_flow *df_ptr;
	
	uint32_t dst_ip;
	uint16_t dst_port;
	uint32_t dst_vni;

	df_ptr = get_dp_flow_ptr(pkt);

	if (df_ptr->flags.flow_type != DP_FLOW_TYPE_INCOMING){
		printf("cannot looup underlay ip of neighboring horizontal nat for non-incoming traffic \n");
		return -1;
	}

	if (df_ptr->l4_type == IPPROTO_ICMP){
		printf("cannot looup underlay ip of neighboring horizontal nat for icmp traffic \n");
		return -1;
	}

	dst_ip=ntohl(df_ptr->dst.dst_addr);
	dst_port=ntohs(df_ptr->dst_port);
	printf("dst port is %d in searching range \n",df_ptr->dst_port);
	printf("dst port is %d in searching range \n",rte_be_to_cpu_16(df_ptr->dst_port));
	dst_vni=df_ptr->tun_info.dst_vni;
	printf("dst port is %d in searching range \n",ntohs(df_ptr->dst_port));

	struct horizontal_nat_entry *current = network_nat_db;

	while (current!=NULL){
		int is_nat_entry_found = dp_check_port_network_nat_entry(current, dst_ip, NULL,dst_vni,dst_port);
		if (is_nat_entry_found){
			memcpy(underlay_ipv6,current->dst_ipv6,sizeof(current->dst_ipv6));
			printf("found in extern nat entry \n");
			return 1;
		}
		current = current->next;
	}

	return 0;
}

uint16_t dp_allocate_hrztl_snat_port(uint32_t vm_ip, uint16_t vm_port, uint32_t vni)
{
	struct nat_key nkey;
	struct network_dnat_key network_key;
	struct snat_data *data;
	uint16_t min_port,max_port, allocated_port=0;

	nkey.ip = vm_ip;
	nkey.vni = vni;

	if (rte_hash_lookup_data(ipv4_snat_tbl, &nkey, (void**)&data) < 0)
		return 0;

	if (data->horizontal_nat_ip == 0)
		return 0;

	min_port = data->horizontal_nat_port_range[0];
	max_port = data->horizontal_nat_port_range[1];

	network_key.nat_ip= data->horizontal_nat_ip;
	network_key.vni=vni;
	
	for (uint16_t p = min_port; p <= max_port; p++){
		network_key.nat_port=p;
		if (rte_hash_lookup(ipv4_network_dnat_tbl, &network_key)==-ENOENT){
			allocated_port=p;
			break;
		}
	}
	
	return allocated_port;
}