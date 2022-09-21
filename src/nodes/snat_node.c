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
	struct rte_udp_hdr	*udp_hdr;
	struct rte_tcp_hdr	*tcp_hdr;
	
	struct dp_flow *df_ptr;
	struct flow_value *cntrack = NULL;
	uint32_t src_ip;
	uint8_t is_ip_snatted=0,is_ip_network_snatted=0;

	df_ptr = get_dp_flow_ptr(m);

	if (df_ptr->conntrack)
		cntrack = df_ptr->conntrack;

	if (!cntrack)
		return 1;

	if (cntrack->flow_state == DP_FLOW_STATE_NEW && cntrack->dir == DP_FLOW_DIR_ORG) {
		printf("new flow in snat \n");
		uint16_t nat_port;
		uint32_t vni =  dp_get_vm_vni(m->port);
		src_ip = ntohl(df_ptr->src.src_addr);
		is_ip_snatted = dp_is_ip_snatted(src_ip,vni);
		is_ip_network_snatted = dp_is_ip_network_snatted(src_ip,vni);
		if ((is_ip_snatted || is_ip_network_snatted) && df_ptr->flags.public_flow == DP_FLOW_SOUTH_NORTH
		    && (cntrack->flow_status == DP_FLOW_STATUS_NONE)) {
			ipv4_hdr = dp_get_ipv4_hdr(m);
			if(is_ip_snatted){
				ipv4_hdr->src_addr = htonl(dp_get_vm_snat_ip(src_ip, vni));
				cntrack->nat_info.nat_type=DP_FLOW_NAT_TYPE_VIP;
			}
			if(is_ip_network_snatted && df_ptr->l4_type != DP_IP_PROTO_ICMP){
				uint16_t src_port;
				if (df_ptr->l4_type == DP_IP_PROTO_TCP){
					tcp_hdr = (struct rte_tcp_hdr*)(ipv4_hdr+1);
					src_port = tcp_hdr->src_port;
				}else if (df_ptr->l4_type == DP_IP_PROTO_UDP) {
					udp_hdr = (struct rte_udp_hdr*)(ipv4_hdr+1);
					src_port = udp_hdr->src_port;
				}
				nat_port = htons(dp_allocate_network_snat_port(src_ip, src_port, vni, df_ptr->l4_type));
				printf("allocate port %d \n",nat_port);
				if (nat_port == 0){
					printf("an invalid network nat port is allocated \n");
					return 0;
				}
				ipv4_hdr->src_addr = htonl(dp_get_vm_network_snat_ip(src_ip, vni));
				
				if (df_ptr->l4_type == DP_IP_PROTO_TCP)
					tcp_hdr->src_port = nat_port;
				else if (df_ptr->l4_type == DP_IP_PROTO_UDP)
					udp_hdr->src_port = nat_port;

				cntrack->nat_info.nat_type=DP_FLOW_NAT_TYPE_NETWORK;
				cntrack->nat_info.vni=vni;
			}
			df_ptr->flags.nat = DP_NAT_CHG_SRC_IP;
			df_ptr->nat_addr = df_ptr->src.src_addr;
			if(is_ip_network_snatted && df_ptr->l4_type != DP_IP_PROTO_ICMP)
				df_ptr->nat_port = nat_port;
			df_ptr->src.src_addr = ipv4_hdr->src_addr;
			dp_nat_chg_ip(df_ptr, ipv4_hdr, m);

			/* Expect the new destination in this conntrack object */
			cntrack->flow_status = DP_FLOW_STATUS_SRC_NAT;
			dp_delete_flow(&cntrack->flow_key[DP_FLOW_DIR_REPLY]);
			cntrack->flow_key[DP_FLOW_DIR_REPLY].ip_dst = ntohl(ipv4_hdr->src_addr);
			if (is_ip_network_snatted && df_ptr->l4_type != DP_IP_PROTO_ICMP)
				cntrack->flow_key[DP_FLOW_DIR_REPLY].port_dst = ntohs(nat_port);
			
			dp_add_flow(&cntrack->flow_key[DP_FLOW_DIR_REPLY]);
			dp_add_flow_data(&cntrack->flow_key[DP_FLOW_DIR_REPLY], cntrack);
		}
		return 1;
	}
	/* We already know what to do */
	if (cntrack->flow_status == DP_FLOW_STATUS_SRC_NAT &&
		cntrack->dir == DP_FLOW_DIR_ORG) {
		printf("existing flow in snat \n");
		ipv4_hdr = dp_get_ipv4_hdr(m);
		ipv4_hdr->src_addr = htonl(cntrack->flow_key[DP_FLOW_DIR_REPLY].ip_dst);

		if(cntrack->nat_info.nat_type==DP_FLOW_NAT_TYPE_NETWORK){
			if (df_ptr->l4_type == DP_IP_PROTO_TCP){
					tcp_hdr = (struct rte_tcp_hdr*)(ipv4_hdr+1);
					tcp_hdr->src_port= htons(cntrack->flow_key[DP_FLOW_DIR_REPLY].port_dst);
				}else if (df_ptr->l4_type == DP_IP_PROTO_UDP) {
					udp_hdr = (struct rte_udp_hdr*)(ipv4_hdr+1);
					udp_hdr->src_port= htons(cntrack->flow_key[DP_FLOW_DIR_REPLY].port_dst);
				}
			df_ptr->nat_port=cntrack->flow_key[DP_FLOW_DIR_REPLY].port_dst;
		}

		df_ptr->flags.nat = DP_NAT_CHG_SRC_IP;
		df_ptr->nat_addr = df_ptr->src.src_addr;
		df_ptr->src.src_addr = ipv4_hdr->src_addr;
		dp_nat_chg_ip(df_ptr, ipv4_hdr, m);
	}

	if (((cntrack->flow_status == DP_FLOW_STATUS_DST_NAT) || (cntrack->flow_status == DP_FLOW_STATUS_DST_LB))
		&& (cntrack->dir == DP_FLOW_DIR_REPLY)) {
		ipv4_hdr = dp_get_ipv4_hdr(m);
		ipv4_hdr->src_addr = htonl(cntrack->flow_key[DP_FLOW_DIR_ORG].ip_dst);
		df_ptr->flags.nat = DP_NAT_CHG_SRC_IP;
		df_ptr->nat_addr = df_ptr->src.src_addr;
		df_ptr->src.src_addr = ipv4_hdr->src_addr;
		dp_nat_chg_ip(df_ptr, ipv4_hdr, m);
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
