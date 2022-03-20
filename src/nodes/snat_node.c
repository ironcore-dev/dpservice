#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_mbuf.h>
#include "dp_mbuf_dyn.h"
#include "dp_lpm.h"
#include "dp_flow.h"
#include "dp_util.h"
#include "nodes/snat_node.h"


static int snat_node_init(const struct rte_graph *graph, struct rte_node *node)
{
	struct snat_node_ctx *ctx = (struct snat_node_ctx *)node->ctx;

	ctx->next = SNAT_NEXT_DROP;


	RTE_SET_USED(graph);

	return 0;
}

static __rte_always_inline int handle_snat(struct rte_mbuf *m)
{
	struct rte_ipv4_hdr *ipv4_hdr;
	struct rte_tcp_hdr *tcp_hdr;
	struct dp_flow *df_ptr;
	struct flow_key key;

	memset(&key, 0, sizeof(struct flow_key));
	df_ptr = get_dp_flow_ptr(m);


	if (df_ptr->flags.nat == DP_NAT_SNAT) {
		if (df_ptr->l4_type == DP_IP_PROTO_TCP) {
			ipv4_hdr = rte_pktmbuf_mtod_offset(m, struct rte_ipv4_hdr *,
											sizeof(struct rte_ether_hdr));
			ipv4_hdr->src_addr = dp_get_vm_nat_ip(m->port);
			tcp_hdr =  (struct rte_tcp_hdr *)(ipv4_hdr + 1);
			ipv4_hdr->hdr_checksum = 0;
			ipv4_hdr->hdr_checksum = rte_ipv4_cksum(ipv4_hdr);
			tcp_hdr->cksum = 0;
			tcp_hdr->cksum = rte_ipv4_udptcp_cksum(ipv4_hdr, tcp_hdr);
			return 0;
		}
	} else if (df_ptr->flags.nat == DP_NAT_DNAT) {
		if (df_ptr->l4_type == DP_IP_PROTO_TCP) {
			ipv4_hdr = rte_pktmbuf_mtod(m, struct rte_ipv4_hdr*);
			tcp_hdr =  (struct rte_tcp_hdr *)(ipv4_hdr + 1);
			dp_build_flow_key(&key, m);
			if (dp_flow_exists(&key)) {
				df_ptr->nxt_hop = dp_get_vm_port_id_per_nat_ip(ntohl(ipv4_hdr->dst_addr));
				if (df_ptr->nxt_hop < 0)
					return -1;
				ipv4_hdr->dst_addr = htonl(dp_get_dhcp_range_ip4(df_ptr->nxt_hop));
				ipv4_hdr->hdr_checksum = 0;
				ipv4_hdr->hdr_checksum = rte_ipv4_cksum(ipv4_hdr);
				tcp_hdr->cksum = 0;
				tcp_hdr->cksum = rte_ipv4_udptcp_cksum(ipv4_hdr, tcp_hdr);;
			}
			return 1;
		}
		return -1;
	} 
	return 1;
}

static __rte_always_inline uint16_t snat_node_process(struct rte_graph *graph,
													 struct rte_node *node,
													 void **objs,
													 uint16_t cnt)
{
	struct rte_mbuf *mbuf0, **pkts;
	rte_edge_t next_index;
	int i, ret;

	pkts = (struct rte_mbuf **)objs;
	/* Speculative next */
	next_index = SNAT_NEXT_DROP;

	for (i = 0; i < cnt; i++) {
		mbuf0 = pkts[i];
		ret = handle_snat(mbuf0);
		if (ret == 1)
			next_index = SNAT_NEXT_L2_DECAP;
		else if (ret == 0)
			next_index = SNAT_NEXT_FIREWALL;

		rte_node_enqueue_x1(graph, node, next_index, mbuf0);
	}	

	return cnt;
}

static struct rte_node_register snat_node_base = {
	.name = "snat",
	.init = snat_node_init,
	.process = snat_node_process,

	.nb_edges = SNAT_NEXT_MAX,
	.next_nodes =
		{
			[SNAT_NEXT_L2_DECAP] = "l2_decap",
			[SNAT_NEXT_FIREWALL] = "firewall",
			[SNAT_NEXT_DROP] = "drop",
		},
};

struct rte_node_register *snat_node_get(void)
{
	return &snat_node_base;
}

RTE_NODE_REGISTER(snat_node_base);
