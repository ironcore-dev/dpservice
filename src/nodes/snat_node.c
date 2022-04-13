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
#include "dp_rte_flow.h"
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
	struct flow_value *cntrack = NULL;
	uint32_t src_ip;

	df_ptr = get_dp_flow_ptr(m);

	if (df_ptr->conntrack)
		cntrack = df_ptr->conntrack;

	if (!cntrack)
		return 1;

	if (cntrack->flow_state == DP_FLOW_STATE_NEW && cntrack->dir == DP_FLOW_DIR_ORG) {
		src_ip = ntohl(df_ptr->src.src_addr);
		if (dp_is_ip_snatted(src_ip, dp_get_vm_vni(m->port))
		    && (cntrack->flow_status == DP_FLOW_STATUS_NONE)) {
			ipv4_hdr = dp_get_ipv4_hdr(m);
			ipv4_hdr->src_addr = htonl(dp_get_vm_snat_ip(src_ip, dp_get_vm_vni(m->port)));
			df_ptr->src.src_addr = ipv4_hdr->src_addr;
			tcp_hdr =  (struct rte_tcp_hdr *)(ipv4_hdr + 1);
			ipv4_hdr->hdr_checksum = 0;
			ipv4_hdr->hdr_checksum = rte_ipv4_cksum(ipv4_hdr);
			tcp_hdr->cksum = 0;
			tcp_hdr->cksum = rte_ipv4_udptcp_cksum(ipv4_hdr, tcp_hdr);

			/* Expect the new destination in this conntrack object */
			cntrack->flow_status = DP_FLOW_STATUS_SRC_NAT;
			dp_delete_flow(&cntrack->flow_key[DP_FLOW_DIR_REPLY]);
			cntrack->flow_key[DP_FLOW_DIR_REPLY].ip_dst = ntohl(ipv4_hdr->src_addr);
			dp_add_flow(&cntrack->flow_key[DP_FLOW_DIR_REPLY]);
			dp_add_flow_data(&cntrack->flow_key[DP_FLOW_DIR_REPLY], cntrack);
		}
		return 1;
	}
	/* We already know what to do */
	if (cntrack->flow_status == DP_FLOW_STATUS_SRC_NAT &&
		cntrack->dir == DP_FLOW_DIR_ORG) {
		ipv4_hdr = dp_get_ipv4_hdr(m);
		ipv4_hdr->src_addr = htonl(cntrack->flow_key[DP_FLOW_DIR_REPLY].ip_dst);
		df_ptr->src.src_addr = ipv4_hdr->src_addr;
		tcp_hdr =  (struct rte_tcp_hdr *)(ipv4_hdr + 1);
		ipv4_hdr->hdr_checksum = 0;
		ipv4_hdr->hdr_checksum = rte_ipv4_cksum(ipv4_hdr);
		tcp_hdr->cksum = 0;
		tcp_hdr->cksum = rte_ipv4_udptcp_cksum(ipv4_hdr, tcp_hdr);
	}

	if (((cntrack->flow_status == DP_FLOW_STATUS_DST_NAT) || (cntrack->flow_status == DP_FLOW_STATUS_DST_LB))
		&& (cntrack->dir == DP_FLOW_DIR_REPLY)) {
		ipv4_hdr = dp_get_ipv4_hdr(m);
		ipv4_hdr->src_addr = htonl(cntrack->flow_key[DP_FLOW_DIR_ORG].ip_dst);
		df_ptr->src.src_addr = ipv4_hdr->src_addr;
		tcp_hdr =  (struct rte_tcp_hdr *)(ipv4_hdr + 1);
		ipv4_hdr->hdr_checksum = 0;
		ipv4_hdr->hdr_checksum = rte_ipv4_cksum(ipv4_hdr);
		tcp_hdr->cksum = 0;
		tcp_hdr->cksum = rte_ipv4_udptcp_cksum(ipv4_hdr, tcp_hdr);
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
			[SNAT_NEXT_FIREWALL] = "firewall",
			[SNAT_NEXT_DROP] = "drop",
		},
};

struct rte_node_register *snat_node_get(void)
{
	return &snat_node_base;
}

RTE_NODE_REGISTER(snat_node_base);
