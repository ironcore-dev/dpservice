#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_mbuf.h>
#include "node_api.h"
#include "nodes/packet_relay_node.h"
#include "dp_mbuf_dyn.h"
#include "dp_lpm.h"
#include "dpdk_layer.h"
#include "rte_flow/dp_rte_flow.h"
#include "dp_util.h"

struct packet_relay_node_main packet_relay_node;

static int packet_relay_node_init(const struct rte_graph *graph, struct rte_node *node)
{
	struct packet_relay_node_ctx *ctx = (struct packet_relay_node_ctx *)node->ctx;

	ctx->next = PACKET_RELAY_NEXT_DROP;

	RTE_SET_USED(graph);

	return 0;
}

static __rte_always_inline int handle_packet_relay(struct rte_mbuf *m)
{
	struct dp_flow *df_ptr;
	uint16_t ret = PACKET_RELAY_NEXT_DROP;
	struct flow_value *cntrack = NULL;

	df_ptr = get_dp_flow_ptr(m);

	if (df_ptr->conntrack)
		cntrack = df_ptr->conntrack;

	if (!cntrack)
		return ret;

	if (df_ptr->l4_type == DP_IP_PROTO_ICMP) {
		DPS_LOG(INFO, DPSERVICE, "received a icmp pkt in relay node \n");
		return ret;
	}

	if (cntrack->nat_info.nat_type == DP_FLOW_NAT_TYPE_NETWORK_NEIGH) {
		df_ptr->flags.flow_type = DP_FLOW_TYPE_OUTGOING;
		// TODO: add flexibility to allow relay packet from a different port
		// df_ptr->nxt_hop = dp_get_pf1_port_id();
		df_ptr->nxt_hop = m->port;
		memcpy(df_ptr->tun_info.ul_dst_addr6, cntrack->nat_info.underlay_dst, sizeof(df_ptr->tun_info.ul_dst_addr6));
		return PACKET_RELAY_NEXT_OVERLAY_SWITCH;
	}

	return ret;
}

static __rte_always_inline uint16_t packet_relay_node_process(struct rte_graph *graph,
																struct rte_node *node,
																void **objs,
																uint16_t cnt)
{
	struct rte_mbuf *mbuf0, **pkts;
	int i, ret;

	pkts = (struct rte_mbuf **)objs;

	for (i = 0; i < cnt; i++) {
		mbuf0 = pkts[i];
		ret = handle_packet_relay(mbuf0);

		rte_node_enqueue_x1(graph, node, ret, mbuf0);
	}

	return cnt;
}

int packet_relay_set_next(uint16_t port_id, uint16_t next_index)
{

	packet_relay_node.next_index[port_id] = next_index;
	return 0;
}

static struct rte_node_register packet_relay_node_base = {
	.name = "packet_relay",
	.init = packet_relay_node_init,
	.process = packet_relay_node_process,

	.nb_edges = PACKET_RELAY_NEXT_MAX,
	.next_nodes = {

			[PACKET_RELAY_NEXT_DROP] = "drop",
			[PACKET_RELAY_NEXT_OVERLAY_SWITCH] = "overlay_switch",
		},
};

struct rte_node_register *packet_relay_node_get(void)
{
	return &packet_relay_node_base;
}

RTE_NODE_REGISTER(packet_relay_node_base);

