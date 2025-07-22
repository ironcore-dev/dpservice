#include "dp_sync.h"

#include "dp_error.h"
// TODO just a test
#include <rte_ether.h>


int dp_sync_create_nat(const struct netnat_portmap_key *portmap_key,
					   const struct netnat_portoverload_tbl_key *portoverload_key)
{
	DPS_LOG_ERR("CREATE NAT",
				_DP_LOG_INT("src_vni", portmap_key->vni),
				_DP_LOG_IPV4("src_ip", portmap_key->src_ip.ipv4), // TODO yes, NAT64 (already soved by the struct)
				_DP_LOG_INT("src_port", portmap_key->iface_src_port),
				_DP_LOG_IPV4("nat_ip",  portoverload_key->nat_ip),
				_DP_LOG_INT("nat_port", portoverload_key->nat_port),
				_DP_LOG_IPV4("dst_ip", portoverload_key->dst_ip),
				_DP_LOG_INT("dst_port", portoverload_key->dst_port),
				_DP_LOG_INT("proto", portoverload_key->l4_type));

	struct dp_dpdk_layer *dp_layer = get_dpdk_layer();
	const struct dp_port *port = dp_get_sync_port();
	struct rte_mbuf *pkt = rte_pktmbuf_alloc(dp_layer->rte_mempool); // TODO separate mempool
	struct rte_mbuf *pkts[1] = { pkt };
	struct rte_ether_hdr *eth_hdr = (struct rte_ether_hdr *)rte_pktmbuf_prepend(pkt, sizeof(struct rte_ether_hdr));
	assert(eth_hdr);
	memset(eth_hdr, 0, sizeof(*eth_hdr));
	rte_ether_addr_copy(&port->own_mac, &eth_hdr->src_addr);
// 	eth_hdr->dst_addr.addr_bytes[0] = 0x02;  // TODO multicast just to be sure?
	eth_hdr->ether_type = htons(0x88B5);
	int ret = rte_eth_tx_burst(port->port_id, 0, pkts, 1);
	if (DP_FAILED(ret)) {
		DPS_LOG_WARNING("Failed", DP_LOG_RET(ret));
		rte_pktmbuf_free(pkt);
	} else
		DPS_LOG_WARNING("Written", DP_LOG_VALUE(ret));

	// TODO: sysctl -w net.ipv6.conf.dpsbr0.disable_ipv6=1
	// this suppresses noise

	// TODO 
	// 34997 0x88B5 IEEE Std 802 - Local Experimental Ethertype    [IEEE]
	// 34998 0x88B6 IEEE Std 802 - Local Experimental Ethertype    [IEEE]
	return DP_OK;
}


int dp_sync_delete_nat(const struct netnat_portmap_key *portmap_key,
					   const struct netnat_portoverload_tbl_key *portoverload_key)
{
	DPS_LOG_ERR("REMOVE NAT",
				_DP_LOG_INT("src_vni", portmap_key->vni),
				_DP_LOG_IPV4("src_ip", portmap_key->src_ip.ipv4), // TODO yes, NAT64 (already soved by the struct)
				_DP_LOG_INT("src_port", portmap_key->iface_src_port),
				_DP_LOG_IPV4("nat_ip",  portoverload_key->nat_ip),
				_DP_LOG_INT("nat_port", portoverload_key->nat_port),
				_DP_LOG_IPV4("dst_ip", portoverload_key->dst_ip),
				_DP_LOG_INT("dst_port", portoverload_key->dst_port),
				_DP_LOG_INT("proto", portoverload_key->l4_type));
	return DP_OK;
}
