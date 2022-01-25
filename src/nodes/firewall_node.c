#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_mbuf.h>
#include "dp_mbuf_dyn.h"
#include "dp_lpm.h"
#include "dp_util.h"
#include "nodes/firewall_node.h"


static int firewall_node_init(const struct rte_graph *graph, struct rte_node *node)
{
	struct firewall_node_ctx *ctx = (struct firewall_node_ctx *)node->ctx;

	ctx->next = FIREWALL_NEXT_DROP;


	RTE_SET_USED(graph);

	return 0;
}

static __rte_always_inline int handle_firewall(struct rte_mbuf *m)
{
	struct underlay_conf *u_conf = get_underlay_conf();
	struct dp_flow *df_ptr;
	struct flow_key key;
	df_ptr = get_dp_flow_ptr(m);

	/* Connections to the outer world are always allowed */
	if (dp_is_pf_port_id(df_ptr->nxt_hop))
		goto pass_packet;

	/* Check other constraints per target VM/port in a helper function */
	if (htons(u_conf->default_port) == df_ptr->dst_port)
		goto pass_packet;

	/* ICMP packets are always allowed */
	if (df_ptr->l4_type == DP_IP_PROTO_ICMP)
		goto pass_packet;

	/* Flows which were already seen are allowed */
	dp_build_flow_key(&key, m);
	if (!dp_flow_exists(df_ptr->nxt_hop, &key))
		return DP_FIREWL_DROP_PACKET;
	else
		return DP_FIREWL_PASS_PACKET;

pass_packet:
	if (!dp_is_pf_port_id(m->port)) {
		dp_build_flow_key(&key, m);
		if (!dp_flow_exists(m->port, &key))
			dp_add_flow(m->port, &key);
	}
	return DP_FIREWL_PASS_PACKET;
}

static __rte_always_inline uint16_t firewall_node_process(struct rte_graph *graph,
													 struct rte_node *node,
													 void **objs,
													 uint16_t cnt)
{
	struct rte_mbuf *mbuf0, **pkts;
	rte_edge_t next_index;
	int i;

	pkts = (struct rte_mbuf **)objs;
	/* Speculative next */
	next_index = FIREWALL_NEXT_DROP;

	for (i = 0; i < cnt; i++) {
		mbuf0 = pkts[i];
		if (handle_firewall(mbuf0))
			next_index = FIREWALL_NEXT_L2_DECAP;
		rte_node_enqueue_x1(graph, node, next_index, mbuf0);
	}	

	return cnt;
}

static struct rte_node_register firewall_node_base = {
	.name = "firewall",
	.init = firewall_node_init,
	.process = firewall_node_process,

	.nb_edges = FIREWALL_NEXT_MAX,
	.next_nodes =
		{
			[FIREWALL_NEXT_L2_DECAP] = "l2_decap",
			[FIREWALL_NEXT_DROP] = "drop",
		},
};

struct rte_node_register *firewall_node_get(void)
{
	return &firewall_node_base;
}

RTE_NODE_REGISTER(firewall_node_base);
