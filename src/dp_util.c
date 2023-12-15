// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#include "dp_util.h"

#include <rte_jhash.h>

#include "dp_conf.h"
#include "dp_error.h"
#include "dp_log.h"
#include "dp_port.h"
#include "rte_flow/dp_rte_flow.h"

#define DP_SYSFS_PREFIX_MLX_DEVICE		"/sys/class/net/"

#define DP_SYSFS_PREFIX_MLX_VF_COUNT	DP_SYSFS_PREFIX_MLX_DEVICE
#define DP_SYSFS_SUFFIX_MLX_VF_COUNT	"/device/sriov_numvfs"

#define DP_SYSFS_PREFIX_MLX_MAX_TX_RATE "/device/sriov/"
#define DP_SYSFS_SUFFIX_MLX_MAX_TX_RATE "/max_tx_rate"
#define DP_SYSFS_MAX_PATH 256

// makes sure there is enough space to prevent collisions
#define DP_JHASH_MARGIN_COEF(ENTRIES) ((uint32_t)((ENTRIES)*1.20))

int dp_get_dev_info(uint16_t port_id, struct rte_eth_dev_info *dev_info, char ifname[IF_NAMESIZE])
{
	int ret;

	ret = rte_eth_dev_info_get(port_id, dev_info);
	if (DP_FAILED(ret)) {
		DPS_LOG_ERR("Cannot get device info", DP_LOG_PORTID(port_id), DP_LOG_RET(ret));
		return DP_ERROR;
	}
	if (!if_indextoname(dev_info->if_index, ifname)) {
		DPS_LOG_ERR("Cannot get device name", DP_LOG_PORTID(port_id), DP_LOG_RET(errno));
		return DP_ERROR;
	}
	return DP_OK;
}

static int get_num_of_vfs_sriov(void)
{
	int vfs;
	char filename[DP_SYSFS_MAX_PATH];
	FILE *fp;

	if (snprintf(filename, sizeof(filename),
				 "%s%s%s",
				 DP_SYSFS_PREFIX_MLX_VF_COUNT,
				 dp_conf_get_pf0_name(),
				 DP_SYSFS_SUFFIX_MLX_VF_COUNT)
			>= (int)sizeof(filename)
	) {
		DPS_LOG_ERR("SR-IOV sysfs path to number of VFs is too long");
		return DP_ERROR;
	}

	fp = fopen(filename, "r");
	if (!fp) {
		DPS_LOG_ERR("Cannot open SR-IOV sysfs path", DP_LOG_RET(errno));
		return DP_ERROR;
	}

	vfs = DP_ERROR;
	if (fscanf(fp, "%d", &vfs) != 1)
		DPS_LOG_ERR("Cannot parse SR-IOV sysfs VF number", DP_LOG_RET(errno));
	fclose(fp);
	return vfs;
}

static int get_num_of_vfs_pattern(void)
{
	int count = 0;
	uint16_t port_id;
	char ifname[IF_NAMESIZE] = {0};
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

int dp_get_num_of_vfs(void)
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
		DPS_LOG_ERR("Too many VFs defined by the kernel", DP_LOG_VALUE(vfs), DP_LOG_MAX(DP_MAX_VF_PORTS));
		return DP_ERROR;
	}
	return vfs;
}


static uint32_t dp_jhash_1word(const void *key, __rte_unused uint32_t length, uint32_t initval)
{
	return rte_jhash_1word(((const uint32_t *)key)[0], initval);
}

static uint32_t dp_jhash_2words(const void *key, __rte_unused uint32_t length, uint32_t initval)
{
	return rte_jhash_2words(((const uint32_t *)key)[0], ((const uint32_t *)key)[1], initval);
}

static uint32_t dp_jhash_3words(const void *key, __rte_unused uint32_t length, uint32_t initval)
{
	return rte_jhash_3words(((const uint32_t *)key)[0], ((const uint32_t *)key)[1], ((const uint32_t *)key)[2], initval);
}

static uint32_t dp_jhash_nwords(const void *key, uint32_t length, uint32_t initval)
{
	return rte_jhash_32b(key, length / 4, initval);
}

struct rte_hash *dp_create_jhash_table(int entries, size_t key_len, const char *name, int socket_id)
{
	struct rte_hash *result;
	char full_name[64];
	rte_hash_function hash_func;

	if (key_len == 4)
		hash_func = dp_jhash_1word;
	else if (key_len == 8)
		hash_func = dp_jhash_2words;
	else if (key_len == 12)
		hash_func = dp_jhash_3words;
	else if (!(key_len % 4))
		hash_func = dp_jhash_nwords;
	else
		hash_func = rte_jhash;

	snprintf(full_name, sizeof(full_name), "%s_%u", name, socket_id);

	struct rte_hash_parameters params = {
		.name = full_name,
		.entries = DP_JHASH_MARGIN_COEF(entries),
		.key_len = (uint32_t)key_len,  // no way this will get bigger than 32b
		.hash_func = hash_func,
		.hash_func_init_val = 0xfee1900d,  // "random" IV
		.socket_id = socket_id,
		.extra_flag = 0,
	};

	result = rte_hash_create(&params);
	if (!result)
		DPS_LOG_ERR("Cannot create jhash table",
					DP_LOG_NAME(name), DP_LOG_SOCKID(socket_id), DP_LOG_RET(rte_errno));

	return result;
}

void dp_free_jhash_table(struct rte_hash *table)
{
	rte_hash_free(table);
}

int dp_set_vf_rate_limit(uint16_t port_id, uint64_t rate)
{
	char filename[DP_SYSFS_MAX_PATH];
	uint16_t vf_pattern_len = 0;
	const char *pattern = dp_conf_get_vf_pattern();
	FILE *fp;
	struct dp_port *port = dp_get_port_by_id(port_id);
	uint64_t rate_in_mbits = rate;

	if (!port) {
		DPS_LOG_ERR("Cannot get port by id", DP_LOG_PORTID(port_id));
		return DP_ERROR;
	}

	while (*(pattern + vf_pattern_len) != '\0')
		vf_pattern_len++;

	if (snprintf(filename, sizeof(filename),
				"%s%s%s%s%s",
				DP_SYSFS_PREFIX_MLX_DEVICE,
				dp_conf_get_pf0_name(),
				DP_SYSFS_PREFIX_MLX_MAX_TX_RATE,
				port->vf_name + vf_pattern_len,
				DP_SYSFS_SUFFIX_MLX_MAX_TX_RATE)
			>= (int)sizeof(filename)
	) {
		DPS_LOG_ERR("SR-IOV sysfs path to vf's max tx rate is too long");
		return DP_ERROR;
	}

	fp = fopen(filename, "w+");
	if (!fp) {
		DPS_LOG_ERR("Cannot open SR-IOV sysfs path to vf's max tx rate", DP_LOG_RET(errno));
		return DP_ERROR;
	}

	fprintf(fp, "%lu\n", rate_in_mbits);
	fclose(fp);

	return DP_OK;
}
