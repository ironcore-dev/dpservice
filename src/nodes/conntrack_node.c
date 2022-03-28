#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_mbuf.h>
#include "dp_mbuf_dyn.h"
#include "dp_lpm.h"
#include "dp_flow.h"
#include "dp_util.h"
#include "dp_rte_flow.h"
#include "nodes/conntrack_node.h"
#include "nodes/dhcp_node.h"


static int conntrack_node_init(const struct rte_graph *graph, struct rte_node *node)
{
	struct conntrack_node_ctx *ctx = (struct conntrack_node_ctx *)node->ctx;

	ctx->next = CONNTRACK_NEXT_DROP;


	RTE_SET_USED(graph);

	return 0;
}

static __rte_always_inline int handle_conntrack(struct rte_mbuf *m)
{
	struct flow_value *flow_val = NULL;
	struct rte_ipv4_hdr *ipv4_hdr;
	struct dp_flow *df_ptr;
	struct flow_key key;
	int ret = 0;

	df_ptr = get_dp_flow_ptr(m);

	if (df_ptr->flags.flow_type == DP_FLOW_TYPE_INCOMING)
		ipv4_hdr = rte_pktmbuf_mtod(m, struct rte_ipv4_hdr *);
	else
		ipv4_hdr = rte_pktmbuf_mtod_offset(m, struct rte_ipv4_hdr *,
										   sizeof(struct rte_ether_hdr));

	if (extract_inner_l3_header(m, ipv4_hdr, 0) < 0)
		return DP_ROUTE_DROP;

	if (extract_inner_l4_header(m, ipv4_hdr + 1, 0) < 0)
		return DP_ROUTE_DROP;

	if (df_ptr->l4_type == DP_IP_PROTO_UDP && ntohs(df_ptr->dst_port) == DP_BOOTP_SRV_PORT)
		return ret;

	if (!dp_is_conntrack_enabled())
		return ret;

	if ((df_ptr->l4_type == DP_IP_PROTO_TCP) || (df_ptr->l4_type == DP_IP_PROTO_UDP)) {
		memset(&key, 0, sizeof(struct flow_key));

		dp_build_flow_key(&key, m);
		if (!dp_flow_exists(&key)) {
			/* Add original direction to conntrack table */
			dp_add_flow(&key);
			flow_val = rte_zmalloc("flow_val", sizeof(struct flow_value), RTE_CACHE_LINE_SIZE);
			printf("Allocate the conntrack %p \n", flow_val);
			rte_atomic32_clear(&flow_val->flow_cnt);
			flow_val->flow_key[DP_FLOW_DIR_ORG] = key;
			flow_val->flow_state = DP_FLOW_STATE_NEW;
			flow_val->flow_status = DP_FLOW_STATUS_NONE;
			flow_val->dir = DP_FLOW_DIR_ORG;
			dp_add_flow_data(&key, flow_val);

			/* Add reply direction to the conntrack table */
			dp_invert_flow_key(&key);
			flow_val->flow_key[DP_FLOW_DIR_REPLY] = key;
			dp_add_flow(&key);
			dp_add_flow_data(&key, flow_val);
		} else {
			dp_get_flow_data(&key, (void**)&flow_val);
			if (dp_are_flows_identical(&key, &flow_val->flow_key[DP_FLOW_DIR_REPLY])) {
				if (flow_val->flow_state == DP_FLOW_STATE_NEW)
					flow_val->flow_state = DP_FLOW_STATE_REPLY;
				flow_val->dir = DP_FLOW_DIR_REPLY;
			}
			if (dp_are_flows_identical(&key, &flow_val->flow_key[DP_FLOW_DIR_ORG])) {
				if (flow_val->flow_state == DP_FLOW_STATE_REPLY)
					flow_val->flow_state = DP_FLOW_STATE_ESTAB;
				flow_val->dir = DP_FLOW_DIR_ORG;
			}
		}
		flow_val->timestamp = rte_rdtsc();
		df_ptr->conntrack = flow_val;
	}
	return ret;
}

static __rte_always_inline uint16_t conntrack_node_process(struct rte_graph *graph,
													 struct rte_node *node,
													 void **objs,
													 uint16_t cnt)
{
	struct rte_mbuf *mbuf0, **pkts;
	int i, route;

	pkts = (struct rte_mbuf **)objs;

	for (i = 0; i < cnt; i++) {
		mbuf0 = pkts[i];
		route = handle_conntrack(mbuf0);

		if (route >= 0) 
			rte_node_enqueue_x1(graph, node, CONNTRACK_NEXT_DNAT, 
								mbuf0);
		else
			rte_node_enqueue_x1(graph, node, CONNTRACK_NEXT_DROP, mbuf0);
	}	

	return cnt;
}

static struct rte_node_register conntrack_node_base = {
	.name = "conntrack",
	.init = conntrack_node_init,
	.process = conntrack_node_process,

	.nb_edges = CONNTRACK_NEXT_MAX,
	.next_nodes =
		{
			[CONNTRACK_NEXT_DNAT] = "dnat",
			//[CONNTRACK_NEXT_LB] = "lb",
			[CONNTRACK_NEXT_DROP] = "drop",
		},
};

struct rte_node_register *conntrack_node_get(void)
{
	return &conntrack_node_base;
}

RTE_NODE_REGISTER(conntrack_node_base);
