#include <rte_common.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_mbuf.h>
#include "dp_flow.h"
#include "dp_log.h"
#include "dp_lpm.h"
#include "dp_mbuf_dyn.h"
#include "dp_nat.h"
#include "nodes/common_node.h"
#include "rte_flow/dp_rte_flow.h"

#define NEXT_NODES(NEXT) \
	NEXT(DNAT_NEXT_IPV4_LOOKUP, "ipv4_lookup") \
	NEXT(DNAT_NEXT_PACKET_RELAY, "packet_relay")
DP_NODE_REGISTER_NOINIT(DNAT, dnat, NEXT_NODES);

static __rte_always_inline rte_edge_t get_next_index(struct rte_node *node, struct rte_mbuf *m)
{
	struct dp_flow *df = dp_get_flow_ptr(m);
	struct flow_value *cntrack = df->conntrack;
	struct rte_ipv4_hdr *ipv4_hdr;
	uint32_t dst_ip, vni, dnat_ip;
	const uint8_t *underlay_dst;
	struct dp_icmp_err_ip_info icmp_err_ip_info;

	if (!cntrack)
		return DNAT_NEXT_IPV4_LOOKUP;

	if (cntrack->flow_state == DP_FLOW_STATE_NEW && df->flags.dir == DP_FLOW_DIR_ORG) {
		dst_ip = ntohl(df->dst.dst_addr);
		vni = df->tun_info.dst_vni == 0 ? dp_get_vm_vni(m->port) : df->tun_info.dst_vni;

		if (dp_is_ip_dnatted(dst_ip, vni) && (cntrack->flow_status == DP_FLOW_STATUS_NONE)) {
			dnat_ip = dp_get_vm_dnat_ip(dst_ip, vni);
			// if it is a network nat pkt
			if (dnat_ip == 0) {
				// extrack identifier field from icmp reply pkt, which is a reply to VM's icmp request
				if (df->l4_type == DP_IP_PROTO_ICMP && df->l4_info.icmp_field.icmp_type == RTE_IP_ICMP_ECHO_REPLY)
					df->l4_info.trans_port.dst_port = df->l4_info.icmp_field.icmp_identifier;
				
				// it is icmp request targeting scalable nat
				if (df->l4_type == DP_IP_PROTO_ICMP && df->l4_info.icmp_field.icmp_type == RTE_IP_ICMP_ECHO_REQUEST) {
					df->flags.nat = DP_NAT_CHG_UL_DST_IP;
					return DNAT_NEXT_PACKET_RELAY;
				}

				// only perform this lookup on unknown dnat (Distributed NAted) traffic flows
				underlay_dst = dp_lookup_network_nat_underlay_ip(df);
				if (underlay_dst) {
					cntrack->nat_info.nat_type = DP_FLOW_NAT_TYPE_NETWORK_NEIGH;
					cntrack->nat_info.l4_type = df->l4_type;
					memcpy(cntrack->nat_info.underlay_dst, underlay_dst, sizeof(cntrack->nat_info.underlay_dst));

					dp_delete_flow_key(&cntrack->flow_key[DP_FLOW_DIR_REPLY]); // no reverse traffic for relaying pkts
					return DNAT_NEXT_PACKET_RELAY;
				}
				
				// if it is not a nat pkt destinated for its neighboring nat, 
				// then it is a premature dnat pkt for network nat (sent before any outgoing traffic from VM, 
				// and it cannot be a standalone new incoming flow for network NAT),
				// silently drop it now.
				return DNAT_NEXT_DROP;
			}

			ipv4_hdr = dp_get_ipv4_hdr(m);
			ipv4_hdr->dst_addr = htonl(dnat_ip);

			df->flags.nat = DP_NAT_CHG_DST_IP;
			df->nat_addr = df->dst.dst_addr;
			df->dst.dst_addr = ipv4_hdr->dst_addr;
			dp_nat_chg_ip(df, ipv4_hdr, m);

			/* Expect the new source in this conntrack object */
			cntrack->flow_status = DP_FLOW_STATUS_DST_NAT;
			dp_delete_flow_key(&cntrack->flow_key[DP_FLOW_DIR_REPLY]);
			cntrack->flow_key[DP_FLOW_DIR_REPLY].ip_src = ntohl(ipv4_hdr->dst_addr);
			dp_add_flow(&cntrack->flow_key[DP_FLOW_DIR_REPLY]);
			dp_add_flow_data(&cntrack->flow_key[DP_FLOW_DIR_REPLY], cntrack);
		}
		return DNAT_NEXT_IPV4_LOOKUP;
	}

	if (cntrack->nat_info.nat_type == DP_FLOW_NAT_TYPE_NETWORK_NEIGH) {
		df->flags.nat = DP_NAT_CHG_UL_DST_IP;
		return DNAT_NEXT_PACKET_RELAY;
	}

	if (cntrack->flow_status == DP_FLOW_STATUS_DST_NAT &&
		df->flags.dir == DP_FLOW_DIR_ORG) {
		ipv4_hdr = dp_get_ipv4_hdr(m);
		ipv4_hdr->dst_addr = htonl(cntrack->flow_key[DP_FLOW_DIR_REPLY].ip_src);
		df->flags.nat = DP_NAT_CHG_DST_IP;
		df->nat_addr = df->dst.dst_addr;
		df->dst.dst_addr = ipv4_hdr->dst_addr;
		dp_nat_chg_ip(df, ipv4_hdr, m);
	}

	/* We already know what to do */
	if (cntrack->flow_status == DP_FLOW_STATUS_SRC_NAT &&
		df->flags.dir == DP_FLOW_DIR_REPLY) {
		ipv4_hdr = dp_get_ipv4_hdr(m);
		ipv4_hdr->dst_addr = htonl(cntrack->flow_key[DP_FLOW_DIR_ORG].ip_src);
		if (cntrack->nat_info.nat_type == DP_FLOW_NAT_TYPE_NETWORK_LOCAL) {
			if (df->l4_type == DP_IP_PROTO_ICMP) {
				if (df->l4_info.icmp_field.icmp_type == RTE_IP_ICMP_ECHO_REPLY) {
					if (dp_change_icmp_identifier(m, cntrack->flow_key[DP_FLOW_DIR_ORG].port_dst) == DP_IP_ICMP_ID_INVALID) {
						DPNODE_LOG_WARNING(node, "Cannot replace ICMP header's identifier with value %d",
								htons(cntrack->flow_key[DP_FLOW_DIR_ORG].port_dst));
						return DNAT_NEXT_DROP;
					}
				}
				if (df->l4_info.icmp_field.icmp_type == DP_IP_ICMP_TYPE_ERROR) {
					memset(&icmp_err_ip_info, 0, sizeof(icmp_err_ip_info));
					dp_get_icmp_err_ip_hdr(m, &icmp_err_ip_info);
					if (!icmp_err_ip_info.err_ipv4_hdr || !icmp_err_ip_info.l4_src_port || !icmp_err_ip_info.l4_dst_port)
						return DNAT_NEXT_DROP;

					icmp_err_ip_info.err_ipv4_hdr->src_addr = htonl(cntrack->flow_key[DP_FLOW_DIR_ORG].ip_src);
					icmp_err_ip_info.err_ipv4_hdr->hdr_checksum = cntrack->nat_info.icmp_err_ip_cksum;
					dp_change_icmp_err_l4_src_port(m, &icmp_err_ip_info, htons(cntrack->flow_key[DP_FLOW_DIR_ORG].src.port_src));
				}
				
			} else {
				if (dp_change_l4_hdr_port(m, DP_L4_PORT_DIR_DST, htons(cntrack->flow_key[DP_FLOW_DIR_ORG].src.port_src)) == 0) {
					DPNODE_LOG_WARNING(node, "Cannot replace L4 header's dst port with value %d",
							htons(cntrack->flow_key[DP_FLOW_DIR_ORG].src.port_src));
					return DNAT_NEXT_DROP;
				}
			}

		}
		df->flags.nat = DP_NAT_CHG_DST_IP;
		df->nat_addr = df->dst.dst_addr; // record nat IP
		df->dst.dst_addr = ipv4_hdr->dst_addr; // store new dst_addr (which is VM's IP)
		dp_nat_chg_ip(df, ipv4_hdr, m);
	}
	return DNAT_NEXT_IPV4_LOOKUP;
}

static uint16_t dnat_node_process(struct rte_graph *graph,
								  struct rte_node *node,
								  void **objs,
								  uint16_t nb_objs)
{
	dp_foreach_graph_packet(graph, node, objs, nb_objs, DNAT_NEXT_IPV4_LOOKUP, get_next_index);
	return nb_objs;
}
