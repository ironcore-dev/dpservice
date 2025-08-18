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
	DPS_LOG_INFO("Sync node switching from backup to active mode");
	backup_mode = false;
}


static __rte_always_inline void process_packet(const struct rte_mbuf *pkt)
{
	struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
	struct dp_sync_hdr *sync_hdr = (struct dp_sync_hdr *)(eth_hdr + 1);
	struct dp_sync_msg_nat_create *nat_create;
	struct dp_sync_msg_nat_delete *nat_delete;
#ifdef ENABLE_VIRTSVC
	struct dp_sync_msg_virtsvc_conn *virtsvc_conn;
#endif

	if (eth_hdr->ether_type != htons(DP_SYNC_ETHERTYPE)) {
		DPS_LOG_WARNING("Invalid sync ethertype", DP_LOG_VALUE(eth_hdr->ether_type));
		return;
	}

	switch (sync_hdr->msg_type) {
	case DP_SYNC_MSG_REQUEST_DUMP:
		DPS_LOG_INFO("Received request for sync table dumps");
		if (backup_mode) {
			DPS_LOG_WARNING("Invalid sync request for backup dpservice");
			break;
		}
		dp_synchronize_local_nat_flows();
#ifdef ENABLE_VIRTSVC
		dp_synchronize_virtsvc_connections();
#endif
		break;
	case DP_SYNC_MSG_NAT_CREATE:
		if (!backup_mode) {
			DPS_LOG_WARNING("Invalid sync NAT create message for active dpservice");
			break;
		}
		nat_create = (struct dp_sync_msg_nat_create *)(sync_hdr + 1);
		dp_allocate_sync_snat_port(&nat_create->portmap_key,
								   &nat_create->portoverload_key,
								   nat_create->created_port_id,
								   nat_create->icmp_type_src,
								   nat_create->icmp_err_ip_cksum);
		// errors ignored, keep processing messages
		break;
	case DP_SYNC_MSG_NAT_DELETE:
		if (!backup_mode) {
			DPS_LOG_WARNING("Invalid sync NAT delete message for active dpservice");
			break;
		}
		nat_delete = (struct dp_sync_msg_nat_delete *)(sync_hdr + 1);
		dp_remove_sync_snat_port(&nat_delete->portmap_key, &nat_delete->portoverload_key);
		// errors ignored, keep processing messages
		break;
	case DP_SYNC_MSG_VIRTSVC_CONN:
#ifdef ENABLE_VIRTSVC
		if (!backup_mode) {
			DPS_LOG_WARNING("Invalid sync VIRTSVC message for active dpservice");
			break;
		}
		virtsvc_conn = (struct dp_sync_msg_virtsvc_conn *)(sync_hdr + 1);
		dp_virtsvc_open_sync_connection(virtsvc_conn->virtual_addr, virtsvc_conn->virtual_port, virtsvc_conn->proto,
										virtsvc_conn->vf_ip, virtsvc_conn->vf_l4_port, virtsvc_conn->vf_port_id,
										virtsvc_conn->conn_port);
		// errors ignored, keep processing messages
		break;
#endif
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

	do {
		n_pkts = rte_eth_rx_burst(sync_port_id, 0, (struct rte_mbuf **)objs, RTE_GRAPH_BURST_SIZE);
		if (likely(!n_pkts))
			return 0;

		for (uint16_t i = 0; i < n_pkts; ++i)
			process_packet(((struct rte_mbuf **)objs)[i]);

		rte_pktmbuf_free_bulk((struct rte_mbuf **)objs, n_pkts);
	// HACK:
	// in backup mode, graph worker is slowed down intentionally
	// so always read the whole burst coming from active dpservice
	} while (backup_mode);

	node->idx = n_pkts;
	return n_pkts;
}
