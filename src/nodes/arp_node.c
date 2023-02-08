#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_graph.h>
#include <rte_arp.h>
#include <rte_graph_worker.h>
#include <rte_mbuf.h>
#include "node_api.h"
#include "nodes/common_node.h"
#include "nodes/arp_node_priv.h"
#include "dp_error.h"
#include "dp_mbuf_dyn.h"
#include "dp_log.h"
#include "dp_lpm.h"


struct arp_node_main arp_node;

static int arp_node_init(const struct rte_graph *graph, struct rte_node *node)
{
	struct arp_node_ctx *ctx = (struct arp_node_ctx *)node->ctx;

	ctx->next = ARP_NEXT_DROP;

	RTE_SET_USED(graph);

	return 0;
}

static __rte_always_inline bool arp_handled(struct rte_mbuf *m)
{
	struct rte_ether_hdr *incoming_eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
	struct rte_arp_hdr *incoming_arp_hdr = (struct rte_arp_hdr *)(incoming_eth_hdr + 1);
	uint32_t requested_ip = ntohl(incoming_arp_hdr->arp_data.arp_tip);
	uint32_t sender_ip = ntohl(incoming_arp_hdr->arp_data.arp_sip);
	struct rte_ether_addr tmp_addr;
	uint32_t temp_ip;

	// ARP reply from VM
	if (dp_arp_cycle_needed(m->port) && (sender_ip == dp_get_dhcp_range_ip4(m->port))) {
		dp_set_neigh_mac(m->port, &incoming_eth_hdr->src_addr);
		return true;
	}

	// unless ARP request for gateway, ignore
	if (ntohs(incoming_arp_hdr->arp_opcode) != DP_ARP_REQUEST || requested_ip != dp_get_gw_ip4())
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
		DPNODE_LOG_ERR(node, "Cannot attach port %d", pkt->port);
		return ARP_NEXT_DROP;
	}

	return arp_node.next_index[pkt->port];
}

static __rte_always_inline uint16_t arp_node_process(struct rte_graph *graph,
													 struct rte_node *node,
													 void **objs,
													 uint16_t nb_objs)
{
	dp_foreach_graph_packet(graph, node, objs, nb_objs, DP_GRAPH_NO_SPECULATED_NODE, get_next_index);
	return nb_objs;
}

int arp_set_next(uint16_t port_id, uint16_t next_index)
{
	arp_node.next_index[port_id] = next_index;
	return 0;
}

static struct rte_node_register arp_node_base = {
	.name = "arp",
	.init = arp_node_init,
	.process = arp_node_process,

	.nb_edges = ARP_NEXT_MAX,
	.next_nodes = {
		
			[ARP_NEXT_DROP] = "drop",
		},
};

struct rte_node_register *arp_node_get(void)
{
	return &arp_node_base;
}

RTE_NODE_REGISTER(arp_node_base);
