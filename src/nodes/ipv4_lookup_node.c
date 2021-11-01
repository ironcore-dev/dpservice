#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>
#include "node_api.h"
#include "nodes/ipv4_lookup_priv.h"
#include "dp_mbuf_dyn.h"

/* Our default route */
#define DP_PF_PORT 0

struct ipv4_lookup_node_main ipv4_lookup_node;

static int ipv4_lookup_node_init(const struct rte_graph *graph, struct rte_node *node)
{
	struct ipv4_lookup_node_ctx *ctx = (struct ipv4_lookup_node_ctx *)node->ctx;

	ctx->next = IPV4_LOOKUP_NEXT_DROP;


	RTE_SET_USED(graph);

	return 0;
}

static __rte_always_inline int prepare_flow(struct rte_mbuf *m, int nh)
{
	struct dp_flow df;
	struct dp_mbuf_priv1 *dp_mbuf_p1 = NULL;
	int res;

	dp_mbuf_p1 = get_dp_mbuf_priv1(m);
	if (!dp_mbuf_p1) {
		printf("Can not get private pointer\n");
		return 0;
	}

	memset(&df, 0, sizeof(struct dp_flow));
	// ATTRIBUTES
	df.attr.ingress = 1;
	df.attr.priority = 0;
	df.attr.transfer = 1;

	// PATTERN: ETHERNET
	struct rte_flow_item_eth eth_spec;
	struct rte_flow_item_eth eth_mask;
	memset(&eth_spec, 0, sizeof(struct rte_flow_item_eth));
	memset(&eth_mask, 0, sizeof(struct rte_flow_item_eth));
	eth_spec.type = htons(0x0800);
	eth_mask.type = htons(0xffff);
	df.pattern[df.pattern_cnt].type = RTE_FLOW_ITEM_TYPE_ETH;
	df.pattern[df.pattern_cnt].spec = &eth_spec;
	df.pattern[df.pattern_cnt].mask = &eth_mask;
	df.pattern_cnt++;

	// PATTERN: IPv4
	struct rte_flow_item_ipv4 ipv4_spec;
	struct rte_flow_item_ipv4 ipv4_mask;
	memset(&ipv4_spec, 0, sizeof(struct rte_flow_item_ipv4));
	memset(&ipv4_mask, 0, sizeof(struct rte_flow_item_ipv4));
	ipv4_spec.hdr.next_proto_id = 1;
	ipv4_spec.hdr.dst_addr = htonl(0xc0a87b05);
	ipv4_mask.hdr.next_proto_id = 0xff;
	ipv4_mask.hdr.dst_addr = 0xffffffff;
	df.pattern[df.pattern_cnt].type = RTE_FLOW_ITEM_TYPE_IPV4;
	df.pattern[df.pattern_cnt].spec = &ipv4_spec;
	df.pattern[df.pattern_cnt].mask = &ipv4_mask;
	df.pattern_cnt++;

	// PATTERN: ICMP
	struct rte_flow_item_icmp icmp_spec;
	struct rte_flow_item_icmp icmp_mask;
	memset(&icmp_spec, 0, sizeof(struct rte_flow_item_icmp));
	memset(&icmp_mask, 0, sizeof(struct rte_flow_item_icmp));
	icmp_spec.hdr.icmp_type = 8; // ECHO Request
	icmp_mask.hdr.icmp_type = 0xff;
	df.pattern[df.pattern_cnt].type = RTE_FLOW_ITEM_TYPE_ICMP;
	df.pattern[df.pattern_cnt].spec = &icmp_spec;
	df.pattern[df.pattern_cnt].mask = &icmp_mask;
	df.pattern_cnt++;

	// PATTERN: END
	df.pattern[df.pattern_cnt].type = RTE_FLOW_ITEM_TYPE_END;
	df.pattern_cnt++;


	// ACTIONS
	df.action[df.action_cnt].type = RTE_FLOW_ACTION_TYPE_RAW_DECAP;
	struct rte_flow_action_raw_decap raw_decap = {.data = NULL, .size = 14};
	df.action[df.action_cnt].conf = &raw_decap;
	df.action_cnt++;

	df.action[df.action_cnt].type = RTE_FLOW_ACTION_TYPE_RAW_ENCAP;

	uint8_t encap_hdr[50] = {0};

	struct rte_ether_hdr *new_eth_hdr = (struct rte_ether_hdr *) encap_hdr;
	uint8_t deadbeef[] = {0x00, 0x00, 0xde, 0xad, 0xbe, 0xef};
	memcpy(new_eth_hdr->s_addr.addr_bytes, deadbeef, 6);
	uint8_t router_mac[] = {0x90, 0x3c, 0xb3, 0x33, 0x83, 0xfd};
	memcpy(new_eth_hdr->d_addr.addr_bytes, router_mac, 6);
	new_eth_hdr->ether_type = htons(0x0800);

	struct rte_ipv4_hdr *new_ipv4_hdr = (struct rte_ipv4_hdr*)(&encap_hdr[14]);
	new_ipv4_hdr->version_ihl = 0x45;
	new_ipv4_hdr->fragment_offset = 0x40;
	new_ipv4_hdr->time_to_live = 64;
	new_ipv4_hdr->next_proto_id = 17;
	new_ipv4_hdr->src_addr = htonl(0x2d569801); // src 45.86.152.1
	new_ipv4_hdr->dst_addr = htonl(0x08080404); // src 45.86.152.1

	struct rte_udp_hdr *new_udp_hdr = (struct rte_udp_hdr*)(new_ipv4_hdr+1);
	new_udp_hdr->src_port = htons(4711);
	new_udp_hdr->dst_port = htons(6081);

	struct rte_flow_item_geneve *new_geneve_hdr = (struct rte_flow_item_geneve*)(new_udp_hdr+1);
	uint8_t vni[] = {0x00, 0x67, 0x12};
	memcpy(new_geneve_hdr->vni, vni, 3);
	new_geneve_hdr->ver_opt_len_o_c_rsvd0 = 0;
	new_geneve_hdr->protocol = htons(0x0800);

	struct rte_flow_action_raw_encap raw_encap = {.data = encap_hdr, .size = 50};
	df.action[df.action_cnt].conf = &raw_encap;
	df.action_cnt++;

	df.action[df.action_cnt].type = RTE_FLOW_ACTION_TYPE_PORT_ID;
	struct rte_flow_action_port_id nport_id = {.original = 0, .reserved= 0, .id = nh};
	df.action[df.action_cnt].conf = &nport_id;
	df.action_cnt++;
	df.action[df.action_cnt].type = RTE_FLOW_ACTION_TYPE_END;
	df.action_cnt++;

	struct rte_flow_error error;
	res = rte_flow_validate(m->port, &df.attr, df.pattern, df.action, &error);

	if (!res) {
		dp_mbuf_p1->flow_ptr = rte_zmalloc(__func__, sizeof(struct dp_flow), RTE_CACHE_LINE_SIZE);
		rte_memcpy(dp_mbuf_p1->flow_ptr, &df, sizeof(struct dp_flow));
		dp_mbuf_p1->flow_ptr->valid = 1;
		printf("Flow validated on port %d targeting port %d \n ", m->port, nh);
	} else {
		printf("Flow can't be validated message: %s\n", error.message ? error.message : "(no stated reason)");
		return 0;
	} 
	
	return 1;
}

static __rte_always_inline int handle_ipv4_lookup(struct rte_mbuf *m, int nh)
{

	prepare_flow(m, nh);

	return 1;
} 

static __rte_always_inline uint16_t ipv4_lookup_node_process(struct rte_graph *graph,
															 struct rte_node *node,
															 void **objs,
															 uint16_t cnt)
{
	struct rte_mbuf *mbuf0, **pkts;
	int i;

	pkts = (struct rte_mbuf **)objs;

	for (i = 0; i < cnt; i++) {
		mbuf0 = pkts[i];
		init_dp_mbuf_priv1(mbuf0);
		if (handle_ipv4_lookup(mbuf0, DP_PF_PORT)) 
			rte_node_enqueue_x1(graph, node, ipv4_lookup_node.next_index[DP_PF_PORT], 
								*objs);
		else
			rte_node_enqueue_x1(graph, node, IPV4_LOOKUP_NEXT_DROP, *objs);
	}	

    return cnt;
}

int ipv4_lookup_set_next(uint16_t port_id, uint16_t next_index)
{

	ipv4_lookup_node.next_index[port_id] = next_index;
	return 0;
}

static struct rte_node_register ipv4_lookup_node_base = {
	.name = "ipv4_lookup",
	.init = ipv4_lookup_node_init,
	.process = ipv4_lookup_node_process,

	.nb_edges = IPV4_LOOKUP_NEXT_MAX,
	.next_nodes =
		{
			[IPV4_LOOKUP_NEXT_DROP] = "drop",
		},
};

struct rte_node_register *ipv4_lookup_node_get(void)
{
	return &ipv4_lookup_node_base;
}

RTE_NODE_REGISTER(ipv4_lookup_node_base);
