#include <rte_common.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_mbuf.h>
#include "dp_error.h"
#include "dp_flow.h"
#include "dp_log.h"
#include "dp_mbuf_dyn.h"
#include "dp_nat.h"
#include "nodes/common_node.h"
#include "rte_flow/dp_rte_flow.h"
#include "dp_internal_stats.h"

#define NEXT_NODES(NEXT) \
	NEXT(SNAT_NEXT_FIREWALL, "firewall")
DP_NODE_REGISTER_NOINIT(SNAT, snat, NEXT_NODES);

static __rte_always_inline rte_edge_t get_next_index(struct rte_node *node, struct rte_mbuf *m)
{
	struct dp_flow *df = dp_get_flow_ptr(m);
	struct flow_value *cntrack = df->conntrack;
	struct rte_ipv4_hdr *ipv4_hdr;
	uint32_t src_ip;
	struct snat_data *snat_data;
	uint16_t nat_port;
	uint32_t vni;
	int ret;

	if (!cntrack)
		return SNAT_NEXT_FIREWALL;

	if (cntrack->flow_state == DP_FLOW_STATE_NEW && df->flags.dir == DP_FLOW_DIR_ORG) {
		src_ip = ntohl(df->src.src_addr);
		vni = dp_get_vm_vni(m->port);
		snat_data = dp_get_vm_snat_data(src_ip, vni);

		if (snat_data && (snat_data->vip_ip != 0 || snat_data->network_nat_ip != 0)
			&& df->flags.public_flow == DP_FLOW_SOUTH_NORTH
		    && cntrack->flow_status == DP_FLOW_STATUS_NONE
		) {
			ipv4_hdr = dp_get_ipv4_hdr(m);
			// TODO(tao?): in case of both VIP and NAT set, VIP gets written here and immediately overwritten by NAT
			if (snat_data->vip_ip != 0) {
				ipv4_hdr->src_addr = htonl(snat_data->vip_ip);
				cntrack->nat_info.nat_type = DP_FLOW_NAT_TYPE_VIP;
			}
			if (snat_data->network_nat_ip != 0) {
				ret = dp_allocate_network_snat_port(df, vni);
				if (DP_FAILED(ret)) {
					DPNODE_LOG_WARNING(node, "Failed to allocate new NAT port for connection",
									   DP_LOG_IPV4(src_ip), DP_LOG_PORT(ntohs(df->l4_info.trans_port.src_port)));
					return SNAT_NEXT_DROP;
				}
				nat_port = htons((uint16_t)ret);
				ipv4_hdr->src_addr = htonl(snat_data->network_nat_ip);

				DP_STATS_NAT_INC_USED_PORT_CNT(m->port);

				if (df->l4_type == DP_IP_PROTO_ICMP) {
					if (dp_change_icmp_identifier(m, ntohs(nat_port)) == DP_IP_ICMP_ID_INVALID) {
						DPNODE_LOG_WARNING(node, "Cannot replace ICMP header's identifier");
						return SNAT_NEXT_DROP;
					}
				} else {
					if (dp_change_l4_hdr_port(m, DP_L4_PORT_DIR_SRC, nat_port) == 0) {
						DPNODE_LOG_WARNING(node, "Cannot replace L4 header's src port");
						return SNAT_NEXT_DROP;
					}
				}

				cntrack->nat_info.nat_type = DP_FLOW_NAT_TYPE_NETWORK_LOCAL;
				cntrack->nat_info.vni = vni;
				cntrack->nat_info.l4_type = df->l4_type;
				cntrack->nat_info.icmp_err_ip_cksum = ipv4_hdr->hdr_checksum;
			}
			df->flags.nat = DP_NAT_CHG_SRC_IP;
			df->nat_addr = ipv4_hdr->src_addr; // nat_addr is the new src_addr in ipv4_hdr
			if (snat_data->network_nat_ip != 0)
				df->nat_port = nat_port;
			dp_nat_chg_ip(df, ipv4_hdr, m);

			/* Expect the new destination in this conntrack object */
			cntrack->flow_status = DP_FLOW_STATUS_SRC_NAT;
			dp_delete_flow_key(&cntrack->flow_key[DP_FLOW_DIR_REPLY]);
			cntrack->flow_key[DP_FLOW_DIR_REPLY].ip_dst = ntohl(ipv4_hdr->src_addr);
			if (snat_data->network_nat_ip != 0)
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
		df->flags.dir == DP_FLOW_DIR_ORG) {
		ipv4_hdr = dp_get_ipv4_hdr(m);
		ipv4_hdr->src_addr = htonl(cntrack->flow_key[DP_FLOW_DIR_REPLY].ip_dst);

		if (cntrack->nat_info.nat_type == DP_FLOW_NAT_TYPE_NETWORK_LOCAL) {
			if (df->l4_type == DP_IP_PROTO_ICMP) {
				if (dp_change_icmp_identifier(m, cntrack->flow_key[DP_FLOW_DIR_REPLY].port_dst) == DP_IP_ICMP_ID_INVALID) {
					DPNODE_LOG_WARNING(node, "Cannot replace ICMP header's identifier");
					return SNAT_NEXT_DROP;
				}
			} else {
				if (dp_change_l4_hdr_port(m, DP_L4_PORT_DIR_SRC, htons(cntrack->flow_key[DP_FLOW_DIR_REPLY].port_dst)) == 0) {
					DPNODE_LOG_WARNING(node, "Cannot replace L4 header's src port");
					return SNAT_NEXT_DROP;
				}
			}

			df->nat_port = cntrack->flow_key[DP_FLOW_DIR_REPLY].port_dst;
		}

		df->flags.nat = DP_NAT_CHG_SRC_IP;
		df->nat_addr = df->src.src_addr;
		df->src.src_addr = ipv4_hdr->src_addr;
		dp_nat_chg_ip(df, ipv4_hdr, m);
	}

	if (((cntrack->flow_status == DP_FLOW_STATUS_DST_NAT) || (cntrack->flow_status == DP_FLOW_STATUS_DST_LB))
		&& (df->flags.dir == DP_FLOW_DIR_REPLY)) {
		ipv4_hdr = dp_get_ipv4_hdr(m);
		df->src.src_addr = ipv4_hdr->src_addr;
		ipv4_hdr->src_addr = htonl(cntrack->flow_key[DP_FLOW_DIR_ORG].ip_dst);
		df->nat_addr = ipv4_hdr->src_addr;
		df->flags.nat = DP_NAT_CHG_SRC_IP;
		dp_nat_chg_ip(df, ipv4_hdr, m);
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
