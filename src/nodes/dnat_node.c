#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_mbuf.h>
#include "dp_mbuf_dyn.h"
#include "dp_lpm.h"
#include "dp_nat.h"
#include "dp_flow.h"
#include "dp_util.h"
#include "rte_flow/dp_rte_flow.h"
#include "nodes/dnat_node.h"

static int dnat_node_init(const struct rte_graph *graph, struct rte_node *node)
{
	struct dnat_node_ctx *ctx = (struct dnat_node_ctx *)node->ctx;

	ctx->next = DNAT_NEXT_DROP;


	RTE_SET_USED(graph);

	return 0;
}

static __rte_always_inline int handle_dnat(struct rte_mbuf *m)
{
	struct rte_ipv4_hdr *ipv4_hdr;
	struct dp_flow *df_ptr;
	struct flow_key key;
	struct flow_value *cntrack = NULL;
	uint32_t dst_ip, vni;
	uint8_t underlay_dst[16];

	memset(&key, 0, sizeof(struct flow_key));
	df_ptr = get_dp_flow_ptr(m);

	if (df_ptr->conntrack)
		cntrack = df_ptr->conntrack;

	if (!cntrack)
		return 1;

	if (cntrack->flow_state == DP_FLOW_STATE_NEW && cntrack->dir == DP_FLOW_DIR_ORG) {
		dst_ip = ntohl(df_ptr->dst.dst_addr);
		if (df_ptr->tun_info.dst_vni == 0)
			vni = dp_get_vm_vni(m->port);
		else
			vni = df_ptr->tun_info.dst_vni;

		if (dp_is_ip_dnatted(dst_ip, vni)
		    && (cntrack->flow_status == DP_FLOW_STATUS_NONE)) {
			uint32_t dnat_ip = dp_get_vm_dnat_ip(dst_ip, vni);
			// it is a network-dnat pkt and it is a icmp pkt, send it to relay node for auto-reply
			if (dnat_ip == 0 && df_ptr->l4_type == DP_IP_PROTO_ICMP) {
				cntrack->nat_info.nat_type = DP_FLOW_NAT_TYPE_NETWORK_NEIGH;
				dp_delete_flow(&cntrack->flow_key[DP_FLOW_DIR_REPLY]); // no reverse traffic for relaying pkts
				return DP_ROUTE_PKT_RELAY;
			}
			// only perform this lookup on unknown dnat (VIP dnat. Distributed NAted) traffic flows
			if (dp_lookup_network_nat_underlay_ip(m, underlay_dst)) {
				cntrack->nat_info.nat_type = DP_FLOW_NAT_TYPE_NETWORK_NEIGH;
				cntrack->nat_info.l4_type = df_ptr->l4_type;
				memcpy(cntrack->nat_info.underlay_dst, underlay_dst, sizeof(cntrack->nat_info.underlay_dst));

				dp_delete_flow(&cntrack->flow_key[DP_FLOW_DIR_REPLY]); // no reverse traffic for relaying pkts
				return DP_ROUTE_PKT_RELAY;
			}
			ipv4_hdr = dp_get_ipv4_hdr(m);
			ipv4_hdr->dst_addr = htonl(dnat_ip);
			df_ptr->flags.nat = DP_NAT_CHG_DST_IP;
			df_ptr->nat_addr = df_ptr->dst.dst_addr;
			df_ptr->dst.dst_addr = ipv4_hdr->dst_addr;
			dp_nat_chg_ip(df_ptr, ipv4_hdr, m);

			/* Expect the new source in this conntrack object */
			cntrack->flow_status = DP_FLOW_STATUS_DST_NAT;
			dp_delete_flow(&cntrack->flow_key[DP_FLOW_DIR_REPLY]);
			cntrack->flow_key[DP_FLOW_DIR_REPLY].ip_src = ntohl(ipv4_hdr->dst_addr);
			dp_add_flow(&cntrack->flow_key[DP_FLOW_DIR_REPLY]);
			dp_add_flow_data(&cntrack->flow_key[DP_FLOW_DIR_REPLY], cntrack);
		}
		return 1;
	}

	if (cntrack->flow_status == DP_FLOW_STATUS_DST_NAT &&
		cntrack->dir == DP_FLOW_DIR_ORG) {
		ipv4_hdr = dp_get_ipv4_hdr(m);
		ipv4_hdr->dst_addr = htonl(cntrack->flow_key[DP_FLOW_DIR_REPLY].ip_src);
		df_ptr->flags.nat = DP_NAT_CHG_DST_IP;
		df_ptr->nat_addr = df_ptr->dst.dst_addr;
		df_ptr->dst.dst_addr = ipv4_hdr->dst_addr;
		dp_nat_chg_ip(df_ptr, ipv4_hdr, m);
	}

	/* We already know what to do */
	if (cntrack->flow_status == DP_FLOW_STATUS_SRC_NAT &&
		cntrack->dir == DP_FLOW_DIR_REPLY) {
		ipv4_hdr = dp_get_ipv4_hdr(m);
		ipv4_hdr->dst_addr = htonl(cntrack->flow_key[DP_FLOW_DIR_ORG].ip_src);
		if (cntrack->nat_info.nat_type == DP_FLOW_NAT_TYPE_NETWORK_LOCAL) {

			if (dp_change_l4_hdr_port(m, DP_L4_PORT_DIR_DST, htons(cntrack->flow_key[DP_FLOW_DIR_ORG].src.port_src)) == 0) {
				DPS_LOG(ERR, DPSERVICE, "Error to replace l4 hdr's dst port with value %d \n", htons(cntrack->flow_key[DP_FLOW_DIR_ORG].src.port_src));
				return 0;
			}
		}
		df_ptr->flags.nat = DP_NAT_CHG_DST_IP;
		df_ptr->nat_addr = df_ptr->dst.dst_addr;
		df_ptr->dst.dst_addr = ipv4_hdr->dst_addr;
		dp_nat_chg_ip(df_ptr, ipv4_hdr, m);
	}
	return 1;
}

static __rte_always_inline uint16_t dnat_node_process(struct rte_graph *graph,
													 struct rte_node *node,
													 void **objs,
													 uint16_t cnt)
{
	struct rte_mbuf *mbuf0, **pkts;
	rte_edge_t next_index;
	int i, ret;

	pkts = (struct rte_mbuf **)objs;
	/* Speculative next */
	next_index = DNAT_NEXT_DROP;

	for (i = 0; i < cnt; i++) {
		mbuf0 = pkts[i];
		ret = handle_dnat(mbuf0);
		if (ret == DP_ROUTE_PKT_RELAY)
			next_index = DNAT_NEXT_PACKET_RELAY;
		else if (ret == 1)
			next_index = DNAT_NEXT_IPV4_LOOKUP;
		else
			next_index = DNAT_NEXT_DROP;
		rte_node_enqueue_x1(graph, node, next_index, mbuf0);
	}

	return cnt;
}

static struct rte_node_register dnat_node_base = {
	.name = "dnat",
	.init = dnat_node_init,
	.process = dnat_node_process,

	.nb_edges = DNAT_NEXT_MAX,
	.next_nodes = {

			[DNAT_NEXT_IPV4_LOOKUP] = "ipv4_lookup",
			[DNAT_NEXT_PACKET_RELAY] = "packet_relay",
			[DNAT_NEXT_DROP] = "drop",
		},
};

struct rte_node_register *dnat_node_get(void)
{
	return &dnat_node_base;
}

RTE_NODE_REGISTER(dnat_node_base);
