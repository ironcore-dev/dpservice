#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_graph.h>
#include <rte_malloc.h>
#include <rte_graph_worker.h>
#include <rte_mbuf.h>
#include "node_api.h"
#include "nodes/tx_node_priv.h"
#include "dp_lpm.h"
#include "dp_mbuf_dyn.h"


static struct ethdev_tx_node_main ethdev_tx_main;

static int tx_node_init(const struct rte_graph *graph, struct rte_node *node)
{
	struct tx_node_ctx *ctx = (struct tx_node_ctx *)node->ctx;
	uint64_t port_id = DP_MAX_PORTS;
	uint16_t i;

	/* Find our port id */
	for (i = 0; i < DP_MAX_PORTS; i++) {
		if (ethdev_tx_main.nodes[i] == node->id) {
			port_id = i;
			break;
		}
	}

	RTE_VERIFY(port_id < DP_MAX_PORTS);

	/* Update port and queue */
	ctx->port_id = port_id;
	ctx->queue_id = graph->id;

	return 0;
}

static __rte_always_inline int handle_offload(struct rte_mbuf *m, struct dp_flow *df)
{
	struct rte_flow_action_set_mac flow_mac;
	struct rte_flow_item_eth eth_spec;
	struct rte_flow_item_eth eth_mask;
	struct rte_flow_item_ipv4 ipv4_spec;
	struct rte_flow_item_ipv4 ipv4_mask;
	struct rte_flow_item_icmp icmp_spec;
	struct rte_flow_item_icmp icmp_mask;
	struct rte_flow_item_tcp tcp_spec;
	struct rte_flow_item_tcp tcp_mask;
	struct rte_flow_item_udp udp_spec;
	struct rte_flow_item_udp udp_mask;
	struct rte_flow *flow;
	int res;

	if (df->nxt_hop != DP_PF_PORT) { 
		memset(&eth_spec, 0, sizeof(struct rte_flow_item_eth));
		memset(&eth_mask, 0, sizeof(struct rte_flow_item_eth));
		eth_spec.type = htons(RTE_ETHER_TYPE_IPV4);
		eth_mask.type = htons(0xffff);
		df->pattern[df->pattern_cnt].type = RTE_FLOW_ITEM_TYPE_ETH;
		df->pattern[df->pattern_cnt].spec = &eth_spec;
		df->pattern[df->pattern_cnt].mask = &eth_mask;
		df->pattern_cnt++;

		memset(&ipv4_spec, 0, sizeof(struct rte_flow_item_ipv4));
		memset(&ipv4_mask, 0, sizeof(struct rte_flow_item_ipv4));
		ipv4_spec.hdr.next_proto_id = df->l4_type;
		ipv4_spec.hdr.dst_addr = df->dst_addr;
		ipv4_mask.hdr.next_proto_id = 0xff;
		ipv4_mask.hdr.dst_addr = 0xffffffff;
		df->pattern[df->pattern_cnt].type = RTE_FLOW_ITEM_TYPE_IPV4;
		df->pattern[df->pattern_cnt].spec = &ipv4_spec;
		df->pattern[df->pattern_cnt].mask = &ipv4_mask;
		df->pattern_cnt++;

		if (df->l4_type == DP_IP_PROTO_TCP) {
			memset(&tcp_spec, 0, sizeof(struct rte_flow_item_tcp));
			memset(&tcp_mask, 0, sizeof(struct rte_flow_item_tcp));
			tcp_spec.hdr.dst_port = df->dst_port;
			tcp_spec.hdr.src_port = df->src_port;
			tcp_mask.hdr.dst_port = 0xffff;
			tcp_mask.hdr.src_port = 0xffff;
			df->pattern[df->pattern_cnt].type = RTE_FLOW_ITEM_TYPE_TCP;
			df->pattern[df->pattern_cnt].spec = &tcp_spec;
			df->pattern[df->pattern_cnt].mask = &tcp_mask;
			df->pattern_cnt++;
		}
		if (df->l4_type == DP_IP_PROTO_UDP) {
			memset(&udp_spec, 0, sizeof(struct rte_flow_item_udp));
			memset(&udp_mask, 0, sizeof(struct rte_flow_item_udp));
			udp_spec.hdr.dst_port = df->dst_port;
			udp_spec.hdr.src_port = df->src_port;
			udp_mask.hdr.dst_port = 0xffff;
			udp_mask.hdr.src_port = 0xffff;
			df->pattern[df->pattern_cnt].type = RTE_FLOW_ITEM_TYPE_UDP;
			df->pattern[df->pattern_cnt].spec = &udp_spec;
			df->pattern[df->pattern_cnt].mask = &udp_mask;
			df->pattern_cnt++;
		}
		if (df->l4_type == DP_IP_PROTO_ICMP) {
			memset(&icmp_spec, 0, sizeof(struct rte_flow_item_icmp));
			memset(&icmp_mask, 0, sizeof(struct rte_flow_item_icmp));
			icmp_spec.hdr.icmp_type = df->icmp_type;
			icmp_mask.hdr.icmp_type = 0xff;
			df->pattern[df->pattern_cnt].type = RTE_FLOW_ITEM_TYPE_ICMP;
			df->pattern[df->pattern_cnt].spec = &icmp_spec;
			df->pattern[df->pattern_cnt].mask = &icmp_mask;
			df->pattern_cnt++;
		}

		df->pattern[df->pattern_cnt].type = RTE_FLOW_ITEM_TYPE_END;
		df->pattern_cnt++;

		df->action[df->action_cnt].type = RTE_FLOW_ACTION_TYPE_SET_MAC_DST;
		rte_ether_addr_copy(dp_get_neigh_mac(df->nxt_hop), (struct rte_ether_addr *)flow_mac.mac_addr);
		df->action[df->action_cnt].conf = &flow_mac;
		df->action_cnt++;
		
		df->action[df->action_cnt].type = RTE_FLOW_ACTION_TYPE_SET_MAC_SRC;
		rte_ether_addr_copy(dp_get_mac(df->nxt_hop), (struct rte_ether_addr *)flow_mac.mac_addr);
		df->action[df->action_cnt].conf = &flow_mac;
		df->action_cnt++;

		df->action[df->action_cnt].type = RTE_FLOW_ACTION_TYPE_PORT_ID;
		struct rte_flow_action_port_id nport_id = {.original = 0, .reserved= 0, .id = df->nxt_hop};
		df->action[df->action_cnt].conf = &nport_id;
		df->action_cnt++;
		df->action[df->action_cnt].type = RTE_FLOW_ACTION_TYPE_END;
		df->action_cnt++;

		struct rte_flow_error error;
		res = rte_flow_validate(m->port, &df->attr, df->pattern, df->action, &error);

		if (res) { 
			printf("Flow can't be validated message: %s\n", error.message ? error.message : "(no stated reason)");
			return 0;
		} else {
			printf("Flow validated on port %d targeting port %d \n ", m->port, df->nxt_hop);
			flow = rte_flow_create(m->port, &df->attr, df->pattern, df->action, &error);
			if (!flow)
				printf("Flow can't be created message: %s\n", error.message ? error.message : "(no stated reason)");
		}
		return 1;
	}

	return 0;
}


static __rte_always_inline int handle_flow(struct rte_mbuf *m)
{
	struct dp_flow *df;

	df = get_dp_flow_ptr(m);
	if (df && df->valid)
		handle_offload(m, df);
	rte_free(df);
	return 1;
}

static __rte_always_inline void rewrite_eth_hdr(struct rte_mbuf *m, uint16_t port_id, uint16_t eth_type)
{
	struct rte_ether_hdr *eth_hdr;
	eth_hdr = (struct rte_ether_hdr *)rte_pktmbuf_prepend(m, sizeof(struct rte_ether_hdr));
	eth_hdr->ether_type = htons(eth_type);
	rte_ether_addr_copy(dp_get_neigh_mac(port_id), &eth_hdr->d_addr);
	rte_ether_addr_copy(dp_get_mac(port_id), &eth_hdr->s_addr);
}

static __rte_always_inline uint16_t tx_node_process(struct rte_graph *graph,
													struct rte_node *node,
													void **objs,
													uint16_t cnt)
{
	struct tx_node_ctx *ctx = (struct tx_node_ctx *)node->ctx;
	struct rte_mbuf *mbuf0, **pkts;
	uint16_t port, queue;
	uint16_t sent_count, i;

	RTE_SET_USED(objs);
	RTE_SET_USED(cnt);

	/* Get Tx port id */
	port = ctx->port_id;
	queue = ctx->queue_id;

	pkts = (struct rte_mbuf **)objs;


	for (i = 0; i < cnt; i++) {
		mbuf0 = pkts[i];
		if (mbuf0->port != port) {
			if (port == DP_PF_PORT) {
				rewrite_eth_hdr(mbuf0, port, RTE_ETHER_TYPE_IPV6);
			} else
				rewrite_eth_hdr(mbuf0, port, RTE_ETHER_TYPE_IPV4);
		}	
		handle_flow(mbuf0);
	}	

	sent_count = rte_eth_tx_burst(port, queue, (struct rte_mbuf **)objs,
				 cnt);

	/* Redirect unsent pkts to drop node */
	if (sent_count != cnt) {
		rte_node_enqueue(graph, node, TX_NEXT_DROP,
				 &objs[sent_count], cnt - sent_count);
	}

	return sent_count;
}

struct ethdev_tx_node_main * tx_node_data_get(void)
{
	return &ethdev_tx_main;
}

static struct rte_node_register tx_node_base = {
	.name = "tx",
	.init = tx_node_init,
	.process = tx_node_process,

	.nb_edges = TX_NEXT_MAX,
	.next_nodes =
		{
			[TX_NEXT_DROP] = "drop",
		},
};

struct rte_node_register *tx_node_get(void)
{
	return &tx_node_base;
}

RTE_NODE_REGISTER(tx_node_base);
