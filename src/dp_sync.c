#include "dp_sync.h"

#include "dp_error.h"
// TODO just a test
#include <rte_ether.h>


// TODO static int dp_sync_send_packet(...)

// TODO condition on when to run - only send packets after being asked? (need the other dpservice and a valid request?)
// but maybe not, just spam anyway??

// TODO actually use the full protocol - REQUEST_UPDATES!

static int dp_sync_send_nat_msg(uint8_t msg_type, const struct netnat_portmap_key *portmap_key,
								 const struct netnat_portoverload_tbl_key *portoverload_key)
{
	struct dp_dpdk_layer *dp_layer = get_dpdk_layer();
	const struct dp_port *port = dp_get_sync_port();
	struct rte_mbuf *pkt = rte_pktmbuf_alloc(dp_layer->rte_mempool); // TODO separate mempool
	struct rte_mbuf *pkts[1] = { pkt };
	struct rte_ether_hdr *eth_hdr = (struct rte_ether_hdr *)rte_pktmbuf_append(pkt, sizeof(struct rte_ether_hdr));
	assert(eth_hdr);
	memset(eth_hdr, 0, sizeof(*eth_hdr));
	rte_ether_addr_copy(&port->own_mac, &eth_hdr->src_addr);
	// destination is left zeroed
	eth_hdr->ether_type = htons(DP_SYNC_ETHERTYPE);

	struct dp_sync_hdr *sync_hdr = (struct dp_sync_hdr *)rte_pktmbuf_append(pkt, sizeof(struct dp_sync_hdr));
	assert(sync_hdr);
	sync_hdr->msg_type = msg_type;

	struct dp_sync_msg_nat_keys *nat_keys = (struct dp_sync_msg_nat_keys *)rte_pktmbuf_append(pkt, sizeof(struct dp_sync_msg_nat_keys));
	assert(nat_keys);
	memcpy(&nat_keys->portmap_key, portmap_key, sizeof(*portmap_key));
	memcpy(&nat_keys->portoverload_key, portoverload_key, sizeof(*portoverload_key));

	// TODO I guess we should append with one call!

	int ret = rte_eth_tx_burst(port->port_id, 0, pkts, 1);
	if (DP_FAILED(ret)) {
		DPS_LOG_WARNING("Failed", DP_LOG_RET(ret));
		rte_pktmbuf_free(pkt);
	} else
		DPS_LOG_WARNING("Written", DP_LOG_VALUE(ret));

	// TODO: sysctl -w net.ipv6.conf.dpsbr0.disable_ipv6=1
	// this suppresses noise

	return DP_OK;  // TODO not sure actually about failures...
}

int dp_sync_send_nat_create(const struct netnat_portmap_key *portmap_key,
							const struct netnat_portoverload_tbl_key *portoverload_key)
{
	DPS_LOG_ERR("CREATE NAT",
				_DP_LOG_INT("src_vni", portmap_key->vni),
				_DP_LOG_IPV4("src_ip", portmap_key->src_ip.ipv4),
				_DP_LOG_INT("src_port", portmap_key->iface_src_port),
				_DP_LOG_IPV4("nat_ip",  portoverload_key->nat_ip),
				_DP_LOG_INT("nat_port", portoverload_key->nat_port),
				_DP_LOG_IPV4("dst_ip", portoverload_key->dst_ip),
				_DP_LOG_INT("dst_port", portoverload_key->dst_port),
				_DP_LOG_INT("proto", portoverload_key->l4_type));

	return dp_sync_send_nat_msg(DP_SYNC_MSG_NAT_CREATE, portmap_key, portoverload_key);
}


int dp_sync_send_nat_delete(const struct netnat_portmap_key *portmap_key,
							const struct netnat_portoverload_tbl_key *portoverload_key)
{
	DPS_LOG_ERR("REMOVE NAT",
				_DP_LOG_INT("src_vni", portmap_key->vni),
				_DP_LOG_IPV4("src_ip", portmap_key->src_ip.ipv4),
				_DP_LOG_INT("src_port", portmap_key->iface_src_port),
				_DP_LOG_IPV4("nat_ip",  portoverload_key->nat_ip),
				_DP_LOG_INT("nat_port", portoverload_key->nat_port),
				_DP_LOG_IPV4("dst_ip", portoverload_key->dst_ip),
				_DP_LOG_INT("dst_port", portoverload_key->dst_port),
				_DP_LOG_INT("proto", portoverload_key->l4_type));

	return dp_sync_send_nat_msg(DP_SYNC_MSG_NAT_DELETE, portmap_key, portoverload_key);
}
