#include "dp_util.h"

#include "rte_flow/dp_rte_flow.h"

#define DP_SYSFS_PREFIX_MLX_VF_COUNT	"/sys/class/net/"
#define DP_SYSFS_SUFFIX_MLX_VF_COUNT	"/device/sriov_numvfs"
#define DP_SYSFS_STR_LEN 256

static uint16_t pf_ports[DP_MAX_PF_PORT][2] = {0};

void dp_add_pf_port_id(uint16_t id)
{
	int i;

	for (i = 0; i < DP_MAX_PF_PORT; i++)
		if (!pf_ports[i][1])
		{
			pf_ports[i][0] = id;
			pf_ports[i][1] = 1;
			return;
		}
}

int dp_get_num_of_vfs()
{
	int ret = DP_ACTIVE_VF_PORT; /* Default value */
	char *filename;
	FILE *fp;

	filename = malloc(DP_SYSFS_STR_LEN);

	if (!filename)
		goto out;

	snprintf(filename, DP_SYSFS_STR_LEN, "%s%s%s", DP_SYSFS_PREFIX_MLX_VF_COUNT,
			 dp_conf_get_pf0_name(), DP_SYSFS_SUFFIX_MLX_VF_COUNT);

	fp = fopen(filename, "r");
	// TODO (freeing filename here makes away with the need for gotos)

	if (!fp)
		goto err;

	// TODO(plague) release complains about not using retval
	fscanf(fp, "%d", &ret);

	fclose(fp);
err:
	free(filename);
out:
	return ret;
}

bool dp_is_pf_port_id(uint16_t id)
{
	int i;

	for (i = 0; i < DP_MAX_PF_PORT; i++)
		if (pf_ports[i][1] && (pf_ports[i][0] == id))
			return true;
	return false;
}

uint16_t dp_get_pf0_port_id()
{
	return pf_ports[0][0];
}

uint16_t dp_get_pf1_port_id()
{
	return pf_ports[1][0];
}

void rewrite_eth_hdr(struct rte_mbuf *m, uint16_t port_id, uint16_t eth_type)
{
	struct rte_ether_hdr *eth_hdr;

	eth_hdr = (struct rte_ether_hdr *)rte_pktmbuf_prepend(m, sizeof(struct rte_ether_hdr));
	rte_ether_addr_copy(dp_get_neigh_mac(port_id), &eth_hdr->dst_addr);
	eth_hdr->ether_type = htons(eth_type);
	rte_ether_addr_copy(dp_get_mac(port_id), &eth_hdr->src_addr);
}


void print_ip(unsigned int ip, char *buf)
{
	snprintf(buf, 18, "%d.%d.%d.%d",
		(ip >> 24) & 0xFF,
		(ip >> 16) & 0xFF,
		(ip >> 8) & 0xFF,
		ip & 0xFF);
}
