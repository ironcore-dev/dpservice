#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_mbuf.h>
#include "node_api.h"
#include "dp_mbuf_dyn.h"
#include "dp_lpm.h"
#include "dpdk_layer.h"

#include "nodes/srv6_common.h"
#include "nodes/srv6_encap_node.h"


static int srv6_encap_node_init(const struct rte_graph *graph, struct rte_node *node)
{
	struct srv6_encap_node_ctx *ctx = (struct srv6_encap_node_ctx *)node->ctx;

	ctx->next = SRV6_ENCAP_NEXT_DROP;

	RTE_SET_USED(graph);

	return 0;
}

static __rte_always_inline int handle_srv6_encap(struct rte_mbuf *m)
{
	// struct underlay_conf *u_conf = get_underlay_conf();
    struct segment_routing_hdr *srv6_hdr;
	struct dp_flow *df;

	srv6_hdr = (struct segment_routing_hdr *)rte_pktmbuf_prepend(m, sizeof(struct segment_routing_hdr));

	if (!srv6_hdr)
		return 0;

	// udp_hdr->dst_port = htons(u_conf->dst_port);
	/* TODO compute here from df values inner 5 tuple a CRC16 hash instead as src port */
	df = get_dp_flow_ptr(m);
	// df->flags.geneve_hdr = 0;
    // df->flags.srv6_hdr = 1;

    srv6_hdr->next_hdr=DP_IP_PROTO_IPv4_ENCAP;
    srv6_hdr->hdr_ext_length=(uint8_t)2;
    srv6_hdr->routing_type=IP6_HDR_ROUTING_TYPE_SEGMENT_ROUTING;
    srv6_hdr->left_segments=0;
    srv6_hdr->last_entry=0;
    srv6_hdr->flags=0x00;
    srv6_hdr->tag=0x00;


    // uint32_t vni_ns = htons(df->dst_vni);
    uint32_t vni_ns =df->tun_info.dst_vni;
    memcpy(srv6_hdr->last_segment.locator,df->tun_info.ul_dst_addr6,8);
    memcpy(srv6_hdr->last_segment.function,&vni_ns,4);
    memset(srv6_hdr->last_segment.function+4,0,4);
	// memcpy(geneve_hdr->vni, &df->dst_vni, sizeof(geneve_hdr->vni));
	// geneve_hdr->ver_opt_len_o_c_rsvd0 = 0;
	// geneve_hdr->protocol = htons(df->l3_type);
	
	return 1;
} 

static __rte_always_inline uint16_t srv6_encap_node_process(struct rte_graph *graph,
													 struct rte_node *node,
													 void **objs,
													 uint16_t cnt)
{
	struct rte_mbuf *mbuf0, **pkts;
	int i;

	pkts = (struct rte_mbuf **)objs;


	for (i = 0; i < cnt; i++) {
		mbuf0 = pkts[i];
		if (handle_srv6_encap(mbuf0))
			rte_node_enqueue_x1(graph, node, SRV6_ENCAP_NEXT_IPV6_ENCAP, mbuf0);
		else
			rte_node_enqueue_x1(graph, node, SRV6_ENCAP_NEXT_DROP, mbuf0);
	}	

    return cnt;
}

static struct rte_node_register srv6_encap_node_base = {
	.name = "srv6_encap",
	.init = srv6_encap_node_init,
	.process = srv6_encap_node_process,

	.nb_edges = SRV6_ENCAP_NEXT_MAX,
	.next_nodes =
		{
			[SRV6_ENCAP_NEXT_DROP] = "drop",
			[SRV6_ENCAP_NEXT_IPV6_ENCAP] = "ipv6_encap",
		},
};

struct rte_node_register *srv6_encap_node_get(void)
{
	return &srv6_encap_node_base;
}

RTE_NODE_REGISTER(srv6_encap_node_base);