#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_mbuf.h>
#include "dp_mbuf_dyn.h"
#include "dp_lpm.h"
#include "dp_flow.h"
#include "dp_util.h"
#include "rte_flow/dp_rte_flow.h"
#include "nodes/conntrack_node.h"
#include "nodes/dhcp_node.h"
#include "dp_nat.h"
#include <stdio.h>
#include <unistd.h>


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
	uint8_t underlay_dst[16];
	int ret = 0;

	df_ptr = get_dp_flow_ptr(m);
	ipv4_hdr = dp_get_ipv4_hdr(m);

	if (extract_inner_l3_header(m, ipv4_hdr, 0) < 0)
		return DP_ROUTE_DROP;

	if (extract_inner_l4_header(m, ipv4_hdr + 1, 0) < 0)
		return DP_ROUTE_DROP;

	if (df_ptr->l4_type == DP_IP_PROTO_UDP && ntohs(df_ptr->dst_port) == DP_BOOTP_SRV_PORT)
		return CONNTRACK_NEXT_DNAT;

	if (!dp_is_conntrack_enabled())
		return CONNTRACK_NEXT_DNAT;

	printf("flow type is %d \n",df_ptr->flags.flow_type);
	if (df_ptr->flags.flow_type == DP_FLOW_TYPE_INCOMING 
		&& ((df_ptr->l4_type == IPPROTO_TCP) || (df_ptr->l4_type == IPPROTO_UDP)) 
		&& dp_lookup_horizontal_nat_underlay_ip(m,underlay_dst)){
		
		printf("need to relay a pkt \n");
		dp_build_flow_key(&key, m);
		if (!dp_flow_exists(&key)) {
			/* Add original direction to conntrack table */
			dp_add_flow(&key);
			flow_val = rte_zmalloc("flow_val", sizeof(struct flow_value), RTE_CACHE_LINE_SIZE);
			rte_atomic32_clear(&flow_val->flow_cnt);
			flow_val->flow_key[DP_FLOW_DIR_ORG] = key;
			flow_val->flow_state = DP_FLOW_STATE_NEW;
			flow_val->flow_status = DP_FLOW_STATUS_NONE;
			flow_val->dir = DP_FLOW_DIR_ORG;
			flow_val->nat_info.nat_type=DP_FLOW_NAT_TYPE_NETWORK;
			memcpy(flow_val->nat_info.underlay_dst,underlay_dst,sizeof(flow_val->nat_info.underlay_dst));
			dp_add_flow_data(&key, flow_val);

			// Only the original flow (outgoing)'s hash value is recorded
			df_ptr->dp_flow_hash = (uint32_t)dp_get_flow_hash_value(&key);
		} else {
			dp_get_flow_data(&key, (void **)&flow_val);
			if (dp_are_flows_identical(&key, &flow_val->flow_key[DP_FLOW_DIR_ORG])) {
				if (flow_val->flow_state == DP_FLOW_STATE_NEW)
					flow_val->flow_state = DP_FLOW_STATE_ESTAB;
				flow_val->dir = DP_FLOW_DIR_ORG;
			}
			df_ptr->dp_flow_hash = (uint32_t)dp_get_flow_hash_value(&key);
		}
		flow_val->timestamp = rte_rdtsc();
		df_ptr->conntrack = flow_val;
		ret = DP_ROUTE_PKT_RELAY;
		return ret;
	}

	if ((df_ptr->l4_type == IPPROTO_TCP) || (df_ptr->l4_type == IPPROTO_UDP)
		|| (df_ptr->l4_type == IPPROTO_ICMP)) {
		memset(&key, 0, sizeof(struct flow_key));

		dp_build_flow_key(&key, m);
		printf("dst port in key %d \n", key.port_dst);
		if (!dp_flow_exists(&key)) {
			printf("new flow in conntrack \n");
			/* Add original direction to conntrack table */
			dp_add_flow(&key);
			flow_val = rte_zmalloc("flow_val", sizeof(struct flow_value), RTE_CACHE_LINE_SIZE);
			rte_atomic32_clear(&flow_val->flow_cnt);
			flow_val->flow_key[DP_FLOW_DIR_ORG] = key;
			flow_val->flow_state = DP_FLOW_STATE_NEW;
			flow_val->flow_status = DP_FLOW_STATUS_NONE;
			flow_val->dir = DP_FLOW_DIR_ORG;
			dp_add_flow_data(&key, flow_val);

			// Only the original flow (outgoing)'s hash value is recorded
			df_ptr->dp_flow_hash = (uint32_t)dp_get_flow_hash_value(&key);

			/* Add reply direction to the conntrack table */
			dp_invert_flow_key(&key);
			flow_val->flow_key[DP_FLOW_DIR_REPLY] = key;
			dp_add_flow(&key);
			dp_add_flow_data(&key, flow_val);
		} else {
			printf("existing flow in conntrack \n");
			dp_get_flow_data(&key, (void **)&flow_val);
			if (dp_are_flows_identical(&key, &flow_val->flow_key[DP_FLOW_DIR_REPLY])) { 
				if (flow_val->flow_state == DP_FLOW_STATE_NEW){
					printf("DP_FLOW_STATE_NEW -> DP_FLOW_STATE_REPLY \n");
					flow_val->flow_state = DP_FLOW_STATE_REPLY;
				}
				flow_val->dir = DP_FLOW_DIR_REPLY;
			}
			if (dp_are_flows_identical(&key, &flow_val->flow_key[DP_FLOW_DIR_ORG])) {
				if (flow_val->flow_state == DP_FLOW_STATE_REPLY){
					printf("DP_FLOW_STATE_REPLY -> DP_FLOW_STATE_ESTAB \n");
					flow_val->flow_state = DP_FLOW_STATE_ESTAB;
				}
				flow_val->dir = DP_FLOW_DIR_ORG;
			}
			df_ptr->dp_flow_hash = (uint32_t)dp_get_flow_hash_value(&key);
		}
		flow_val->timestamp = rte_rdtsc();

		df_ptr->conntrack = flow_val;
	}
	if (df_ptr->flags.flow_type == DP_FLOW_TYPE_INCOMING)
		return CONNTRACK_NEXT_LB;

	return CONNTRACK_NEXT_DNAT;
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

		if (route >= 0) {
			rte_node_enqueue_x1(graph, node, route,
								mbuf0);
		}
		else if (route == DP_ROUTE_PKT_RELAY){
			printf("send to relay node \n");
			sleep(3);
			rte_node_enqueue_x1(graph, node, CONNTRACK_NEXT_PACKET_RELAY, mbuf0);
		}
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
	.next_nodes = {
			[CONNTRACK_NEXT_LB] = "lb",
			[CONNTRACK_NEXT_DNAT] = "dnat",
			[CONNTRACK_NEXT_PACKET_RELAY] = "packet_relay",
			[CONNTRACK_NEXT_DROP] = "drop",
		},
};

struct rte_node_register *conntrack_node_get(void)
{
	return &conntrack_node_base;
}

RTE_NODE_REGISTER(conntrack_node_base);
