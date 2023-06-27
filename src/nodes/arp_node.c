#include "nodes/arp_node.h"
#include <netinet/in.h>
#include <rte_arp.h>
#include <rte_common.h>
#include <rte_graph.h>
#include <rte_mbuf.h>
#include "dp_error.h"
#include "dp_log.h"
#include "dp_lpm.h"
#include "nodes/common_node.h"

DP_NODE_REGISTER(ARP, arp, DP_NODE_DEFAULT_NEXT_ONLY);

static uint16_t next_tx_index[DP_MAX_PORTS];

int arp_node_append_vf_tx(uint16_t port_id, const char *tx_node_name)
{
	return dp_node_append_vf_tx(DP_NODE_GET_SELF(arp), next_tx_index, port_id, tx_node_name);
}

// constant after init, precompute
static rte_be32_t gateway_ipv4_nl;

static int arp_node_init(__rte_unused const struct rte_graph *graph, __rte_unused struct rte_node *node)
{
	gateway_ipv4_nl = htonl(dp_get_gw_ip4());
	return DP_OK;
}

static __rte_always_inline bool arp_handled(struct rte_mbuf *m)
{
	struct rte_ether_hdr *incoming_eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
	struct rte_arp_hdr *incoming_arp_hdr = (struct rte_arp_hdr *)(incoming_eth_hdr + 1);
	rte_be32_t requested_ip = incoming_arp_hdr->arp_data.arp_tip;
	rte_be32_t sender_ip = incoming_arp_hdr->arp_data.arp_sip;
	struct rte_ether_addr tmp_addr;
	uint32_t temp_ip;

	// ARP reply from VM
	if (dp_arp_cycle_needed(m->port) && sender_ip == htonl(dp_get_dhcp_range_ip4(m->port))) {
		dp_set_neigh_mac(m->port, &incoming_eth_hdr->src_addr);
		return true;
	}

	// unless ARP request for gateway, ignore
	if (ntohs(incoming_arp_hdr->arp_opcode) != DP_ARP_REQUEST || requested_ip != gateway_ipv4_nl)
		return false;

	// respond back to origin address from this address (reuse the packet)
	rte_ether_addr_copy(&incoming_arp_hdr->arp_data.arp_sha, &incoming_eth_hdr->dst_addr);
	rte_memcpy(incoming_eth_hdr->src_addr.addr_bytes, dp_get_mac(m->port), RTE_ETHER_ADDR_LEN);
	incoming_arp_hdr->arp_opcode = htons(DP_ARP_REPLY);
	rte_memcpy(tmp_addr.addr_bytes, incoming_arp_hdr->arp_data.arp_sha.addr_bytes, RTE_ETHER_ADDR_LEN);
	rte_memcpy(incoming_arp_hdr->arp_data.arp_sha.addr_bytes, dp_get_mac(m->port), RTE_ETHER_ADDR_LEN);
	temp_ip = incoming_arp_hdr->arp_data.arp_sip;
	incoming_arp_hdr->arp_data.arp_sip = incoming_arp_hdr->arp_data.arp_tip;
	incoming_arp_hdr->arp_data.arp_tip = temp_ip;
	rte_ether_addr_copy(&tmp_addr, &incoming_arp_hdr->arp_data.arp_tha);
	return true;
}

static __rte_always_inline rte_edge_t get_next_index(struct rte_node *node, struct rte_mbuf *pkt)
{
	if (!arp_handled(pkt))
		return ARP_NEXT_DROP;

	if (DP_FAILED(dp_port_set_vf_attach_status(pkt->port, DP_VF_PORT_ATTACHED))) {
		DPNODE_LOG_ERR(node, "Cannot attach port", DP_LOG_PORTID(pkt->port));
		return ARP_NEXT_DROP;
	}

	return next_tx_index[pkt->port];
}

static __rte_always_inline uint16_t arp_node_process(struct rte_graph *graph,
													 struct rte_node *node,
													 void **objs,
													 uint16_t nb_objs)
{
	dp_foreach_graph_packet(graph, node, objs, nb_objs, DP_GRAPH_NO_SPECULATED_NODE, get_next_index);
	return nb_objs;
}
