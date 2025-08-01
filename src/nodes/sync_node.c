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


void sync_node_switch_role(void)
{
	backup_mode = false;
	// TODO but also request DUMP!!!
}


static __rte_always_inline void process_packet(const struct rte_mbuf *pkt)
{
	struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
	struct dp_sync_hdr *sync_hdr = (struct dp_sync_hdr *)(eth_hdr + 1);
	struct dp_sync_msg_nat_keys *nat_keys;  // TODO subfunc?

	if (eth_hdr->ether_type != htons(DP_SYNC_ETHERTYPE)) {
		// TODO remove
		// TODO look into ways of getting rid of these packets
		// --> looks like this is only at the start, chich makes sense in pytest, devices are configure AFTER dpservice starts
		DPS_LOG_ERR("Invalid ethertype", DP_LOG_VALUE(eth_hdr->ether_type));
		return;
	}

	// TODO move to function handlers I think
	// BACKUP MODE - listen for NAT table updates
	// ACTIVE MODE - listen for NAT table dump requests
	if (!backup_mode) {
		DPS_LOG_DEBUG("Ignoring sync traffic packet");
		return;
	} // TODO else of course

	switch (sync_hdr->msg_type) {
	case DP_SYNC_MSG_REQUEST_UPDATES:
		DPS_LOG_ERR("TODO request updates");
		break;
	case DP_SYNC_MSG_NAT_CREATE:
		// TODO subfunc?
		nat_keys = (struct dp_sync_msg_nat_keys *)(sync_hdr + 1);
		// TODO cleanup debug
// 		DPS_LOG_WARNING("CREATE NAT",
// 				_DP_LOG_INT("src_vni", nat_keys->portmap_key.vni),
// 				_DP_LOG_IPV4("src_ip", nat_keys->portmap_key.src_ip.ipv4),
// 				_DP_LOG_INT("src_port", nat_keys->portmap_key.iface_src_port),
// 				_DP_LOG_IPV4("nat_ip",  nat_keys->portoverload_key.nat_ip),
// 				_DP_LOG_INT("nat_port", nat_keys->portoverload_key.nat_port),
// 				_DP_LOG_IPV4("dst_ip", nat_keys->portoverload_key.dst_ip),
// 				_DP_LOG_INT("dst_port", nat_keys->portoverload_key.dst_port),
// 				_DP_LOG_INT("proto", nat_keys->portoverload_key.l4_type));
		// TODO actually create it! :)
		dp_allocate_sync_snat_port(&nat_keys->portmap_key, &nat_keys->portoverload_key);
		break;
	case DP_SYNC_MSG_NAT_DELETE:
		// TODO subfunc?
		nat_keys = (struct dp_sync_msg_nat_keys *)(sync_hdr + 1);
		// TODO cleanup debug
// 		DPS_LOG_WARNING("DELETE NAT",
// 				_DP_LOG_INT("src_vni", nat_keys->portmap_key.vni),
// 				_DP_LOG_IPV4("src_ip", nat_keys->portmap_key.src_ip.ipv4),
// 				_DP_LOG_INT("src_port", nat_keys->portmap_key.iface_src_port),
// 				_DP_LOG_IPV4("nat_ip",  nat_keys->portoverload_key.nat_ip),
// 				_DP_LOG_INT("nat_port", nat_keys->portoverload_key.nat_port),
// 				_DP_LOG_IPV4("dst_ip", nat_keys->portoverload_key.dst_ip),
// 				_DP_LOG_INT("dst_port", nat_keys->portoverload_key.dst_port),
// 				_DP_LOG_INT("proto", nat_keys->portoverload_key.l4_type));
		// TODO actually delete it! :)
		dp_remove_sync_snat_port(&nat_keys->portmap_key, &nat_keys->portoverload_key);
		break;
	default:
		DPS_LOG_ERR("Unknown SYNC message type", DP_LOG_VALUE(sync_hdr->msg_type));
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
