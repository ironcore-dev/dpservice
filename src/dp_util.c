#include "dp_util.h"

#include "rte_flow/dp_rte_flow.h"
#include "dp_log.h"
#include "dp_error.h"

#define DP_SYSFS_PREFIX_MLX_VF_COUNT	"/sys/class/net/"
#define DP_SYSFS_SUFFIX_MLX_VF_COUNT	"/device/sriov_numvfs"
#define DP_SYSFS_MAX_PATH 256

int dp_get_dev_info(uint16_t port_id, struct rte_eth_dev_info *dev_info, char ifname[IFNAMSIZ])
{
	int ret;

	ret = rte_eth_dev_info_get(port_id, dev_info);
	if (DP_FAILED(ret)) {
		DPS_LOG_ERR("Cannot get device info for port %u %s", port_id, dp_strerror(ret));
		return DP_ERROR;
	}
	if (!if_indextoname(dev_info->if_index, ifname)) {
		DPS_LOG_ERR("Cannot get device name for port %u %s", port_id, dp_strerror(errno));
		return DP_ERROR;
	}
	return DP_OK;
}

static int get_num_of_vfs_sriov()
{
	int vfs;
	char filename[DP_SYSFS_MAX_PATH];
	FILE *fp;

	if (snprintf(filename, sizeof(filename),
				 "%s%s%s",
				 DP_SYSFS_PREFIX_MLX_VF_COUNT,
				 dp_conf_get_pf0_name(),
				 DP_SYSFS_SUFFIX_MLX_VF_COUNT)
			>= sizeof(filename)
	) {
		DPS_LOG_ERR("SR-IOV sysfs path to number of VFs is too long");
		return DP_ERROR;
	}

	fp = fopen(filename, "r");
	if (!fp) {
		DPS_LOG_ERR("Cannot open SR-IOV sysfs path %s", dp_strerror(errno));
		return DP_ERROR;
	}

	vfs = DP_ERROR;
	if (fscanf(fp, "%d", &vfs) != 1)
		DPS_LOG_ERR("Cannot parse SR-IOV sysfs VF number %s", dp_strerror(errno));
	fclose(fp);
	return vfs;
}

static int get_num_of_vfs_pattern()
{
	int count = 0;
	uint16_t port_id;
	char ifname[IFNAMSIZ] = {0};
	struct rte_eth_dev_info dev_info;
	const char *pattern = dp_conf_get_vf_pattern();

	RTE_ETH_FOREACH_DEV(port_id) {
		if (DP_FAILED(dp_get_dev_info(port_id, &dev_info, ifname)))
			return DP_ERROR;
		if (strstr(ifname, pattern))
			count++;
	}
	return count;
}

int dp_get_num_of_vfs()
{
	int vfs = dp_conf_get_nic_type() == DP_CONF_NIC_TYPE_TAP
		? get_num_of_vfs_pattern()
		: get_num_of_vfs_sriov();

	if (DP_FAILED(vfs)) {
		return DP_ERROR;
	} else if (vfs == 0) {
		DPS_LOG_ERR("No VFs defined by the kernel");
		return DP_ERROR;
	} else if (vfs > DP_MAX_VF_PORTS) {
		DPS_LOG_ERR("Too many VFs defined by the kernel (%d, maximum %d supported)", vfs, DP_MAX_VF_PORTS);
		return DP_ERROR;
	}
	return vfs;
}

int rewrite_eth_hdr(struct rte_mbuf *m, uint16_t port_id, uint16_t eth_type)
{
	struct rte_ether_hdr *eth_hdr;

	eth_hdr = (struct rte_ether_hdr *)rte_pktmbuf_prepend(m, sizeof(struct rte_ether_hdr));
	if (unlikely(!eth_hdr))
		return DP_ERROR;

	m->packet_type |= RTE_PTYPE_L2_ETHER;
	rte_ether_addr_copy(dp_get_neigh_mac(port_id), &eth_hdr->dst_addr);
	eth_hdr->ether_type = htons(eth_type);
	rte_ether_addr_copy(dp_get_mac(port_id), &eth_hdr->src_addr);
	return DP_OK;
}


void dp_fill_ipv4_print_buff(unsigned int ip, char *buf)
{
	snprintf(buf, 18, "%d.%d.%d.%d",
		(ip >> 24) & 0xFF,
		(ip >> 16) & 0xFF,
		(ip >> 8) & 0xFF,
		ip & 0xFF);
}

struct rte_hash *dp_create_jhash_table(int entries, size_t key_len, const char *name, int socket_id)
{
	struct rte_hash *result;
	char full_name[64];

	snprintf(full_name, sizeof(full_name), "%s_%u", name, socket_id);

	struct rte_hash_parameters params = {
		.name = full_name,
		.entries = FLOW_MAX,
		.key_len = key_len,
		.hash_func = rte_jhash,
		.hash_func_init_val = 0xfee1900d,  // "random" IV
		.socket_id = socket_id,
		.extra_flag = 0,
	};

	result = rte_hash_create(&params);
	if (!result)
		DPS_LOG_ERR("Cannot create '%s' jhash table on socket %u %s", name, socket_id, dp_strerror(rte_errno));

	return result;
}
