#include "dp_sync.h"

#include "dp_error.h"
#include <rte_ether.h>

#define DP_SYNC_HEADERS_LEN (sizeof(struct rte_ether_hdr) + sizeof(struct dp_sync_hdr))

// TODO condition on when to run - only send packets after being asked? (need the other dpservice and a valid request?)
// but maybe not, just spam anyway??
// also this is already checked elsewhere I think - validate this

static struct rte_mbuf *dp_sync_alloc_message(uint8_t msg_type, uint16_t payload_len)
{
	struct dp_dpdk_layer *dp_layer = get_dpdk_layer();
	const struct dp_port *port = dp_get_sync_port();
	struct rte_mbuf *pkt;
	struct rte_ether_hdr *eth_hdr;
	struct dp_sync_hdr *sync_hdr;

	pkt = rte_pktmbuf_alloc(dp_layer->rte_mempool);
	if (!pkt) {
		DPS_LOG_ERR("Failed to allocate sync packet");
		return NULL;
	}

	eth_hdr = (struct rte_ether_hdr *)rte_pktmbuf_append(pkt, DP_SYNC_HEADERS_LEN + payload_len);
	if (!eth_hdr) {
		DPS_LOG_ERR("Failed to allocate sync packet payload");
		rte_pktmbuf_free(pkt);
		return NULL;
	}
	rte_ether_addr_copy(&port->own_mac, &eth_hdr->src_addr);
	rte_ether_addr_copy(&port->neigh_mac, &eth_hdr->src_addr);
	eth_hdr->ether_type = htons(DP_SYNC_ETHERTYPE);

	sync_hdr = (struct dp_sync_hdr *)(eth_hdr + 1);
	sync_hdr->msg_type = msg_type;

	return pkt;
}

static int dp_sync_send_message(struct rte_mbuf *pkt)
{
	const struct dp_port *port = dp_get_sync_port();
	struct rte_mbuf *pkts[1] = { pkt };
	int sent;

	sent = rte_eth_tx_burst(port->port_id, 0, pkts, 1);
	if (sent != 1) {
		DPS_LOG_WARNING("Failed to send sync packet");
		rte_pktmbuf_free(pkt);
	}

	return DP_OK;
}


static int dp_sync_send_nat_msg(uint8_t msg_type, const struct netnat_portmap_key *portmap_key,
								const struct netnat_portoverload_tbl_key *portoverload_key)
{
	struct rte_mbuf *pkt;
	struct dp_sync_msg_nat_keys *nat_keys;

	pkt = dp_sync_alloc_message(msg_type, sizeof(*nat_keys));
	if (!pkt)
		return DP_ERROR;

	nat_keys = rte_pktmbuf_mtod_offset(pkt, struct dp_sync_msg_nat_keys *, DP_SYNC_HEADERS_LEN);
	memcpy(&nat_keys->portmap_key, portmap_key, sizeof(*portmap_key));
	memcpy(&nat_keys->portoverload_key, portoverload_key, sizeof(*portoverload_key));

	return dp_sync_send_message(pkt);
}

int dp_sync_send_nat_create(const struct netnat_portmap_key *portmap_key,
							const struct netnat_portoverload_tbl_key *portoverload_key)
{
	return dp_sync_send_nat_msg(DP_SYNC_MSG_NAT_CREATE, portmap_key, portoverload_key);
}

int dp_sync_send_nat_delete(const struct netnat_portmap_key *portmap_key,
							const struct netnat_portoverload_tbl_key *portoverload_key)
{
	return dp_sync_send_nat_msg(DP_SYNC_MSG_NAT_DELETE, portmap_key, portoverload_key);
}


int dp_sync_send_request_dump(void)
{
	struct rte_mbuf *pkt;

	pkt = dp_sync_alloc_message(DP_SYNC_MSG_REQUEST_DUMP, 0);
	if (!pkt)
		return DP_ERROR;

	return dp_sync_send_message(pkt);
}
