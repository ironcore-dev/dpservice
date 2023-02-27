#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_mbuf.h>
#include "dp_mbuf_dyn.h"
#include "dp_lpm.h"
#include "dp_nat.h"
#include "dp_flow.h"
#include "dp_log.h"
#include "rte_flow/dp_rte_flow.h"
#include "nodes/common_node.h"
#include "nodes/snat_node.h"
#include "dp_error.h"


static int snat_node_init(const struct rte_graph *graph, struct rte_node *node)
{
	struct snat_node_ctx *ctx = (struct snat_node_ctx *)node->ctx;

	ctx->next = SNAT_NEXT_DROP;

	RTE_SET_USED(graph);

	return 0;
}

static __rte_always_inline rte_edge_t get_next_index(struct rte_node *node, struct rte_mbuf *m)
{
	struct dp_flow *df_ptr = get_dp_flow_ptr(m);
	struct flow_value *cntrack = df_ptr->conntrack;
	struct rte_ipv4_hdr *ipv4_hdr;
	uint32_t src_ip;
	struct nat_check_result nat_check;
	char printed_ip_buf[18] = {0};
	int ret;

	if (!cntrack)
		return SNAT_NEXT_FIREWALL;

	if (cntrack->flow_state == DP_FLOW_STATE_NEW && cntrack->dir == DP_FLOW_DIR_ORG) {
		uint16_t nat_port;
		uint32_t vni =  dp_get_vm_vni(m->port);
		src_ip = ntohl(df_ptr->src.src_addr);
		if (DP_FAILED(dp_check_if_ip_natted(src_ip, vni, &nat_check))) {
			DPNODE_LOG_WARNING(node, "Failed to perform snat table searching");
			return SNAT_NEXT_DROP;
		}

		if ((nat_check.is_vip_natted || nat_check.is_network_natted) && df_ptr->flags.public_flow == DP_FLOW_SOUTH_NORTH
		    && (cntrack->flow_status == DP_FLOW_STATUS_NONE)) {
			ipv4_hdr = dp_get_ipv4_hdr(m);
			if (nat_check.is_vip_natted) {
				ipv4_hdr->src_addr = htonl(dp_get_vm_snat_ip(src_ip, vni));
				cntrack->nat_info.nat_type = DP_FLOW_NAT_TYPE_VIP;
			}

			if (nat_check.is_network_natted) {
				ret = dp_allocate_network_snat_port(df_ptr, vni);
				if (DP_FAILED(ret)) {
					dp_fill_ipv4_print_buff(src_ip, printed_ip_buf);
					DPNODE_LOG_WARNING(node, "Failed to allocate a valid network nat port for %s:%d",
									   printed_ip_buf, ntohs(df_ptr->l4_info.trans_port.src_port));
					return SNAT_NEXT_DROP;
				}
				nat_port = htons((uint16_t)ret);
				ipv4_hdr->src_addr = htonl(dp_get_vm_network_snat_ip(src_ip, vni));

				if (df_ptr->l4_type == DP_IP_PROTO_ICMP) {
					if (dp_change_icmp_identifier(m, ntohs(nat_port)) == DP_IP_ICMP_ID_INVALID) {
						DPNODE_LOG_WARNING(node, "Cannot replace ICMP header's identifier with value %d", nat_port);
						return SNAT_NEXT_DROP;
					}
				} else {
					if (dp_change_l4_hdr_port(m, DP_L4_PORT_DIR_SRC, nat_port) == 0) {
						DPNODE_LOG_WARNING(node, "Cannot replace L4 header's src port with value %d", nat_port);
						return SNAT_NEXT_DROP;
					}
				}

				cntrack->nat_info.nat_type = DP_FLOW_NAT_TYPE_NETWORK_LOCAL;
				cntrack->nat_info.vni = vni;
				cntrack->nat_info.l4_type = df_ptr->l4_type;
				cntrack->nat_info.icmp_err_ip_cksum = ipv4_hdr->hdr_checksum;
			}
			df_ptr->flags.nat = DP_NAT_CHG_SRC_IP;
			df_ptr->nat_addr = ipv4_hdr->src_addr; // nat_addr is the new src_addr in ipv4_hdr
			if (nat_check.is_network_natted)
				df_ptr->nat_port = nat_port;
			dp_nat_chg_ip(df_ptr, ipv4_hdr, m);

			/* Expect the new destination in this conntrack object */
			cntrack->flow_status = DP_FLOW_STATUS_SRC_NAT;
			dp_delete_flow_key(&cntrack->flow_key[DP_FLOW_DIR_REPLY]);
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
				if (dp_change_icmp_identifier(m, cntrack->flow_key[DP_FLOW_DIR_REPLY].port_dst) == DP_IP_ICMP_ID_INVALID) {
					DPNODE_LOG_WARNING(node, "Cannot replace ICMP header's identifier with value %d",
							htons(cntrack->flow_key[DP_FLOW_DIR_REPLY].port_dst));
					return SNAT_NEXT_DROP;
				}
			} else {
				if (dp_change_l4_hdr_port(m, DP_L4_PORT_DIR_SRC, htons(cntrack->flow_key[DP_FLOW_DIR_REPLY].port_dst)) == 0) {
					DPNODE_LOG_WARNING(node, "Cannot replace L4 header's src port with value %d",
							htons(cntrack->flow_key[DP_FLOW_DIR_REPLY].port_dst));
					return SNAT_NEXT_DROP;
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
		df_ptr->src.src_addr = ipv4_hdr->src_addr;
		ipv4_hdr->src_addr = htonl(cntrack->flow_key[DP_FLOW_DIR_ORG].ip_dst);
		df_ptr->nat_addr = ipv4_hdr->src_addr;
		df_ptr->flags.nat = DP_NAT_CHG_SRC_IP;
		dp_nat_chg_ip(df_ptr, ipv4_hdr, m);
	}

	return SNAT_NEXT_FIREWALL;
}

static uint16_t snat_node_process(struct rte_graph *graph,
								  struct rte_node *node,
								  void **objs,
								  uint16_t nb_objs)
{
	dp_foreach_graph_packet(graph, node, objs, nb_objs, SNAT_NEXT_FIREWALL, get_next_index);
	return nb_objs;
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
