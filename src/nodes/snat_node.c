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
#include "dp_util.h"
#include "dp_debug.h"


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
	struct dp_flow *df_ptr;
	struct flow_value *cntrack = NULL;
	uint32_t src_ip;
	struct nat_check_result nat_check;

	df_ptr = get_dp_flow_ptr(m);

	if (df_ptr->conntrack)
		cntrack = df_ptr->conntrack;

	if (!cntrack)
		return 1;

	if (cntrack->flow_state == DP_FLOW_STATE_NEW && cntrack->dir == DP_FLOW_DIR_ORG) {
		uint16_t nat_port;
		uint32_t vni =  dp_get_vm_vni(m->port);
		src_ip = ntohl(df_ptr->src.src_addr);
		dp_check_if_ip_natted(src_ip, vni, &nat_check);
		if ((nat_check.is_vip_natted || nat_check.is_network_natted) && df_ptr->flags.public_flow == DP_FLOW_SOUTH_NORTH
		    && (cntrack->flow_status == DP_FLOW_STATUS_NONE)) {
			ipv4_hdr = dp_get_ipv4_hdr(m);
			if (nat_check.is_vip_natted) {
				ipv4_hdr->src_addr = htonl(dp_get_vm_snat_ip(src_ip, vni));
				cntrack->nat_info.nat_type = DP_FLOW_NAT_TYPE_VIP;
			}

			if (nat_check.is_network_natted) {
				nat_port = htons(dp_allocate_network_snat_port(src_ip, df_ptr->src_port, vni, df_ptr->l4_type));
				if (nat_port == 0) {
					DPS_LOG(ERR, DPSERVICE, "an invalid network nat port is allocated \n");
					return 0;
				}
				ipv4_hdr->src_addr = htonl(dp_get_vm_network_snat_ip(src_ip, vni));

				if (df_ptr->l4_type == DP_IP_PROTO_ICMP) {
					if (dp_change_icmp_identifier(m, ntohs(nat_port)) == 65535) {
						DPS_LOG(ERR, DPSERVICE, "Error to replace icmp hdr's identifier with value %d \n", nat_port);
						return 0;
					}
				} else {
					if (dp_change_l4_hdr_port(m, DP_L4_PORT_DIR_SRC, nat_port) == 0) {
						DPS_LOG(ERR, DPSERVICE, "Error to replace l4 hdr's src port with value %d \n", nat_port);
						return 0;
					}
				}

				cntrack->nat_info.nat_type = DP_FLOW_NAT_TYPE_NETWORK_LOCAL;
				cntrack->nat_info.vni = vni;
				cntrack->nat_info.l4_type = df_ptr->l4_type;
				cntrack->nat_info.icmp_err_ip_cksum = ipv4_hdr->hdr_checksum;
			}
			df_ptr->flags.nat = DP_NAT_CHG_SRC_IP;
			df_ptr->nat_addr = df_ptr->src.src_addr;
			if (nat_check.is_network_natted)
				df_ptr->nat_port = nat_port;
			df_ptr->src.src_addr = ipv4_hdr->src_addr;
			dp_nat_chg_ip(df_ptr, ipv4_hdr, m);

			/* Expect the new destination in this conntrack object */
			cntrack->flow_status = DP_FLOW_STATUS_SRC_NAT;
			dp_delete_flow(&cntrack->flow_key[DP_FLOW_DIR_REPLY]);
			cntrack->flow_key[DP_FLOW_DIR_REPLY].ip_dst = ntohl(ipv4_hdr->src_addr);
			if (nat_check.is_network_natted)
				cntrack->flow_key[DP_FLOW_DIR_REPLY].port_dst = ntohs(nat_port);

			dp_add_flow(&cntrack->flow_key[DP_FLOW_DIR_REPLY]);
			dp_add_flow_data(&cntrack->flow_key[DP_FLOW_DIR_REPLY], cntrack);
		}
		// it is deleted due the case where an init packet/request is sent twice, and no action is done if it is returned here
		// it has to continue to the follow-up code
		// return 1;
	}

	/* We already know what to do */
	if (cntrack->flow_status == DP_FLOW_STATUS_SRC_NAT &&
		cntrack->dir == DP_FLOW_DIR_ORG) {
		ipv4_hdr = dp_get_ipv4_hdr(m);
		ipv4_hdr->src_addr = htonl(cntrack->flow_key[DP_FLOW_DIR_REPLY].ip_dst);

		if (cntrack->nat_info.nat_type == DP_FLOW_NAT_TYPE_NETWORK_LOCAL) {
			if (df_ptr->l4_type == DP_IP_PROTO_ICMP) {
				if (dp_change_icmp_identifier(m, cntrack->flow_key[DP_FLOW_DIR_REPLY].port_dst) == 65535) {
					DPS_LOG(ERR, DPSERVICE, "Error to replace icmp hdr's identifier with value %d \n", 
							htons(cntrack->flow_key[DP_FLOW_DIR_REPLY].port_dst));
					return 0;
				}
			} else {
				if (dp_change_l4_hdr_port(m, DP_L4_PORT_DIR_SRC, htons(cntrack->flow_key[DP_FLOW_DIR_REPLY].port_dst)) == 0) {
					DPS_LOG(ERR, DPSERVICE, "Error to replace l4 hdr's src port with value %d \n", 
							htons(cntrack->flow_key[DP_FLOW_DIR_REPLY].port_dst));
					return 0;
				}
			}

			df_ptr->nat_port = cntrack->flow_key[DP_FLOW_DIR_REPLY].port_dst;
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
	int i;

	pkts = (struct rte_mbuf **)objs;

	for (i = 0; i < cnt; i++) {
		mbuf0 = pkts[i];
		GRAPHTRACE_PKT(node, mbuf0);
		if (handle_snat(mbuf0) == 1)
			next_index = SNAT_NEXT_FIREWALL;
		else
			next_index = SNAT_NEXT_DROP;
		GRAPHTRACE_PKT_NEXT(node, mbuf0, next_index);
		rte_node_enqueue_x1(graph, node, next_index, mbuf0);
	}

	return cnt;
}

static struct rte_node_register snat_node_base = {
	.name = "snat",
	.init = snat_node_init,
	.process = snat_node_process,

	.nb_edges = SNAT_NEXT_MAX,
	.next_nodes = {

			[SNAT_NEXT_FIREWALL] = "firewall",
			[SNAT_NEXT_DROP] = "drop",
		},
};

struct rte_node_register *snat_node_get(void)
{
	return &snat_node_base;
}

RTE_NODE_REGISTER(snat_node_base);
