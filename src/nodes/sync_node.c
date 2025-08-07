// SPDX-FileCopyrightText: 2025 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#include "nodes/sync_node.h"
#include "dp_error.h"
#include "dp_sync.h"
#include "nodes/common_node.h"

DP_NODE_REGISTER_SOURCE(SYNC, sync, DP_NODE_DEFAULT_NEXT_ONLY);

static volatile bool backup_mode = true;
static uint16_t sync_port_id;

static int sync_node_init(__rte_unused const struct rte_graph *graph, __rte_unused struct rte_node *node)
{
	sync_port_id = dp_get_sync_port()->port_id;
	return DP_OK;
}


void sync_node_switch_mode(void)
{
	backup_mode = false;
}


static __rte_always_inline void process_packet(const struct rte_mbuf *pkt)
{
	struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
	struct dp_sync_hdr *sync_hdr = (struct dp_sync_hdr *)(eth_hdr + 1);
	struct dp_sync_msg_nat_data *nat_data;

	if (eth_hdr->ether_type != htons(DP_SYNC_ETHERTYPE)) {
		DPS_LOG_WARNING("Invalid sync ethertype", DP_LOG_VALUE(eth_hdr->ether_type));
		return;
	}

	switch (sync_hdr->msg_type) {
	case DP_SYNC_MSG_REQUEST_DUMP:
		DPS_LOG_INFO("Received request for sync table dumps");
		if (backup_mode) {
			DPS_LOG_ERR("Invalid sync request for backup dpservice");
			break;
		}
		dp_sync_local_nat_flows();
		break;
	case DP_SYNC_MSG_NAT_CREATE:
		// TODO mute one or both! (otherwise move to info and maybe better texts)
		DPS_LOG_DEBUG("Received NAT create message");
		if (!backup_mode) {
			DPS_LOG_ERR("Invalid sync NAT create message for active dpservice");
			break;
		}
		nat_data = (struct dp_sync_msg_nat_data *)(sync_hdr + 1);
		// errors ignored, keep processing messages
		dp_allocate_sync_snat_port(&nat_data->portmap_key, &nat_data->portoverload_key, nat_data->created_port_id);
		break;
	case DP_SYNC_MSG_NAT_DELETE:
		// TODO mute one or both! (otherwise move to info and maybe better texts)
		DPS_LOG_DEBUG("Received NAT delete message");
		if (!backup_mode) {
			DPS_LOG_ERR("Invalid sync NAT delete message for active dpservice");
			break;
		}
		nat_data = (struct dp_sync_msg_nat_data *)(sync_hdr + 1);
		// errors ignored, keep processing messages
		dp_remove_sync_snat_port(&nat_data->portmap_key, &nat_data->portoverload_key);
		break;
	default:
		DPS_LOG_ERR("Unknown sync message type", DP_LOG_VALUE(sync_hdr->msg_type));
	}
}

static uint16_t sync_node_process(struct rte_graph *graph,
								  struct rte_node *node,
								  void **objs,
								  uint16_t nb_objs)
{
	uint16_t n_pkts;

	RTE_SET_USED(graph);
	RTE_SET_USED(nb_objs);  // this is a source node, input data is not present yet

	n_pkts = rte_eth_rx_burst(sync_port_id, 0, (struct rte_mbuf **)objs, RTE_GRAPH_BURST_SIZE);
	if (likely(!n_pkts))
		return 0;

	for (uint16_t i = 0; i < n_pkts; ++i)
		process_packet(((struct rte_mbuf **)objs)[i]);

	rte_pktmbuf_free_bulk((struct rte_mbuf **)objs, n_pkts);

	node->idx = n_pkts;
	return n_pkts;
}
