#include <rte_common.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_mbuf.h>
#include "dp_mbuf_dyn.h"
#include "dp_nat.h"
#include "nodes/common_node.h"
#include "rte_flow/dp_rte_flow.h"

#define NEXT_NODES(NEXT) \
	NEXT(PACKET_RELAY_NEXT_OVERLAY_SWITCH, "overlay_switch")
DP_NODE_REGISTER_NOINIT(PACKET_RELAY, packet_relay, NEXT_NODES);

static __rte_always_inline rte_edge_t lb_nnat_icmp_reply(struct dp_flow *df, struct rte_mbuf *m)
{
	struct rte_ipv4_hdr *ipv4_hdr = dp_get_ipv4_hdr(m);
	struct rte_icmp_hdr *icmp_hdr = (struct rte_icmp_hdr *)(ipv4_hdr + 1);
	uint32_t temp_ip;
	uint32_t cksum;

	if (icmp_hdr->icmp_type != RTE_IP_ICMP_ECHO_REQUEST)
		return PACKET_RELAY_NEXT_DROP;

	// rewrite the packet and send it back
	icmp_hdr->icmp_type = RTE_IP_ICMP_ECHO_REPLY;

	cksum = ~icmp_hdr->icmp_cksum & 0xffff;
	cksum += ~RTE_BE16(RTE_IP_ICMP_ECHO_REQUEST << 8) & 0xffff;
	cksum += RTE_BE16(RTE_IP_ICMP_ECHO_REPLY << 8);
	cksum = (cksum & 0xffff) + (cksum >> 16);
	cksum = (cksum & 0xffff) + (cksum >> 16);
	icmp_hdr->icmp_cksum = ~cksum;

	temp_ip = ipv4_hdr->dst_addr;
	ipv4_hdr->dst_addr = ipv4_hdr->src_addr;
	ipv4_hdr->src_addr = temp_ip;
	df->flags.flow_type = DP_FLOW_TYPE_OUTGOING;
	df->nxt_hop = m->port;
	dp_nat_chg_ip(df, ipv4_hdr, m);
	memcpy(df->tun_info.ul_dst_addr6, df->tun_info.ul_src_addr6, sizeof(df->tun_info.ul_dst_addr6));

	return PACKET_RELAY_NEXT_OVERLAY_SWITCH;
}


static __rte_always_inline rte_edge_t get_next_index(__rte_unused struct rte_node *node, struct rte_mbuf *m)
{
	struct dp_flow *df = dp_get_flow_ptr(m);
	struct flow_value *cntrack = df->conntrack;

	if (!cntrack)
		return PACKET_RELAY_NEXT_DROP;

	if (cntrack->nf_info.nat_type == DP_FLOW_NAT_TYPE_NETWORK_NEIGH) {
		df->flags.flow_type = DP_FLOW_TYPE_OUTGOING;
		df->nxt_hop = m->port;
		// trick: use src place to store old dst address for offloading
		rte_memcpy(df->tun_info.ul_src_addr6, df->tun_info.ul_dst_addr6, sizeof(df->tun_info.ul_src_addr6));
		rte_memcpy(df->tun_info.ul_dst_addr6, cntrack->nf_info.underlay_dst, sizeof(df->tun_info.ul_dst_addr6));
		return PACKET_RELAY_NEXT_OVERLAY_SWITCH;
	}

	if (df->l4_type == DP_IP_PROTO_ICMP)
		return lb_nnat_icmp_reply(df, m);

	return PACKET_RELAY_NEXT_DROP;
}

static uint16_t packet_relay_node_process(struct rte_graph *graph,
										  struct rte_node *node,
										  void **objs,
										  uint16_t nb_objs)
{
	dp_foreach_graph_packet(graph, node, objs, nb_objs, PACKET_RELAY_NEXT_OVERLAY_SWITCH, get_next_index);
	return nb_objs;
}
