#include "nodes/virtsvc_node.h"
#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_graph.h>
#include <rte_arp.h>
#include <rte_graph_worker.h>
#include <rte_mbuf.h>
#include "dp_error.h"
#include "dp_log.h"
#include "dp_mbuf_dyn.h"
#include "nodes/common_node.h"
#include "rte_flow/dp_rte_flow.h"

DP_NODE_REGISTER(VIRTSVC, virtsvc, DP_NODE_DEFAULT_NEXT_ONLY);

static uint16_t next_tx_index[DP_MAX_PORTS];

int virtsvc_node_append_tx(uint16_t port_id, const char *tx_node_name)
{
	return dp_node_append_tx(DP_NODE_GET_SELF(virtsvc), next_tx_index, port_id, tx_node_name);
}

// runtime constant, precompute
static struct underlay_conf *underlay_conf;

static int virtsvc_node_init(__rte_unused const struct rte_graph *graph, __rte_unused struct rte_node *node)
{
	underlay_conf = get_underlay_conf();
	return DP_OK;
}

static __rte_always_inline void virtsvc_tcp_state_change(struct dp_virtsvc_conn *conn, uint8_t tcp_flags)
{
	if (DP_TCP_PKT_FLAG_RST(tcp_flags)) {
		conn->state = DP_VIRTSVC_CONN_TRANSIENT;
	} else if (DP_TCP_PKT_FLAG_FIN(tcp_flags)) {
		conn->state = DP_VIRTSVC_CONN_TRANSIENT;
	} else {
		switch (conn->state) {
		case DP_VIRTSVC_CONN_TRANSIENT:
			if (DP_TCP_PKT_FLAG_SYN(tcp_flags))
				conn->state = DP_VIRTSVC_CONN_TRANSIENT_SYN;
			break;
		case DP_VIRTSVC_CONN_TRANSIENT_SYN:
			if (DP_TCP_PKT_FLAG_SYNACK(tcp_flags))
				conn->state = DP_VIRTSVC_CONN_TRANSIENT_SYNACK;
			break;
		case DP_VIRTSVC_CONN_TRANSIENT_SYNACK:
			if (DP_TCP_PKT_FLAG_ACK(tcp_flags))
				conn->state = DP_VIRTSVC_CONN_ESTABLISHED;
			break;
		case DP_VIRTSVC_CONN_ESTABLISHED:
			break;
		}
	}
}

static __rte_always_inline rte_be16_t virtsvc_get_port_for_conn(int conn_idx)
{
	return htons(conn_idx + DP_NB_SYSTEM_PORTS);
}

static __rte_always_inline uint16_t virtsvc_request_next(struct rte_node *node,
														 struct rte_mbuf *m,
														 struct dp_flow *df)
{
	struct rte_ipv4_hdr *ipv4_hdr = (struct rte_ipv4_hdr *)rte_pktmbuf_mtod(m, struct rte_ipv4_hdr *);
	rte_be16_t payload_len = htons(ntohs(ipv4_hdr->total_length) - sizeof(struct rte_ipv4_hdr));
	rte_be32_t original_ip = ipv4_hdr->src_addr;
	uint8_t proto = ipv4_hdr->next_proto_id;
	uint8_t ttl = ipv4_hdr->time_to_live;
	struct rte_ipv6_hdr *ipv6_hdr;
	struct rte_tcp_hdr *tcp_hdr;
	struct rte_udp_hdr *udp_hdr;
	struct dp_virtsvc *virtsvc = df->virtsvc;
	struct dp_virtsvc_conn *conn;
	uint16_t pf_port_id;
	int conn_idx;

	// replace IPv4 header with IPv6 header
	rte_pktmbuf_adj(m, (uint16_t)sizeof(struct rte_ipv4_hdr));
	ipv6_hdr = (struct rte_ipv6_hdr *)rte_pktmbuf_prepend(m, sizeof(struct rte_ipv6_hdr));
	if (unlikely(!ipv6_hdr)) {
		DPNODE_LOG_WARNING(node, "No more space in the packet for IPv6 header");
		return VIRTSVC_NEXT_DROP;
	}
	m->packet_type = (m->packet_type & RTE_PTYPE_L4_MASK) | RTE_PTYPE_L3_IPV6;

	// TODO(plague): discuss a PR for endian-dependent definitions
	ipv6_hdr->vtc_flow = htonl(DP_IP6_VTC_FLOW);
	ipv6_hdr->payload_len = payload_len;
	ipv6_hdr->proto = proto;
	ipv6_hdr->hop_limits = ttl;
	rte_memcpy(ipv6_hdr->src_addr, underlay_conf->src_ip6, sizeof(ipv6_hdr->src_addr));
	rte_memcpy(ipv6_hdr->dst_addr, virtsvc->service_addr, sizeof(virtsvc->service_addr));
	m->ol_flags |= RTE_MBUF_F_TX_IPV6;
	m->tx_offload = 0;
	m->l2_len = sizeof(struct rte_ether_hdr);
	m->l3_len = sizeof(struct rte_ipv6_hdr);

	if (proto == IPPROTO_TCP) {
		tcp_hdr = (struct rte_tcp_hdr *)(ipv6_hdr + 1);

		if (DP_FAILED(dp_virtsvc_get_pf_route(virtsvc,
											  m->port, original_ip, tcp_hdr->src_port,
											  &pf_port_id, &conn_idx))
		) {
			DPNODE_LOG_WARNING(node, "Cannot establish outgoing connection");
			return VIRTSVC_NEXT_DROP;
		}
		conn = &virtsvc->connections[conn_idx];
		conn->last_pkt_timestamp = rte_get_timer_cycles();
		virtsvc_tcp_state_change(conn, tcp_hdr->tcp_flags);

		tcp_hdr->src_port = virtsvc_get_port_for_conn(conn_idx);
		tcp_hdr->dst_port = virtsvc->service_port;
		tcp_hdr->cksum = 0;
		m->ol_flags |= RTE_MBUF_F_TX_TCP_CKSUM;
		m->l4_len = DP_TCP_HDR_LEN(tcp_hdr);
	} else {
		udp_hdr = (struct rte_udp_hdr *)(ipv6_hdr + 1);

		if (DP_FAILED(dp_virtsvc_get_pf_route(virtsvc,
											  m->port, original_ip, udp_hdr->src_port,
											  &pf_port_id, &conn_idx))
		) {
			DPNODE_LOG_WARNING(node, "Cannot establish outgoing connection");
			return VIRTSVC_NEXT_DROP;
		}
		conn = &virtsvc->connections[conn_idx];
		conn->last_pkt_timestamp = rte_get_timer_cycles();

		udp_hdr->src_port = virtsvc_get_port_for_conn(conn_idx);
		udp_hdr->dst_port = virtsvc->service_port;
		udp_hdr->dgram_cksum = 0;
		m->ol_flags |= RTE_MBUF_F_TX_UDP_CKSUM;
		m->l4_len = sizeof(struct rte_udp_hdr);
	}

	return next_tx_index[pf_port_id];
}

static __rte_always_inline struct dp_virtsvc_conn *virtsvc_get_conn_on_port(struct dp_virtsvc *virtsvc, rte_be16_t l4_port)
{
	uint16_t port_idx = ntohs(l4_port) - DP_NB_SYSTEM_PORTS;

	return &virtsvc->connections[port_idx];
}

static __rte_always_inline uint16_t virtsvc_reply_next(struct rte_node *node,
													   struct rte_mbuf *m,
													   struct dp_flow *df)
{
	static rte_be16_t packet_id = 0;

	struct rte_ipv6_hdr *ipv6_hdr = rte_pktmbuf_mtod(m, struct rte_ipv6_hdr *);
	uint8_t proto = ipv6_hdr->proto;
	uint8_t ttl = ipv6_hdr->hop_limits;
	struct rte_ipv4_hdr *ipv4_hdr;
	struct rte_tcp_hdr *tcp_hdr;
	struct rte_udp_hdr *udp_hdr;
	uint16_t vf_port_id;
	struct dp_virtsvc_conn *conn;

	// replace IPv6 header with IPv4 header
	rte_pktmbuf_adj(m, sizeof(struct rte_ipv6_hdr));
	ipv4_hdr = (struct rte_ipv4_hdr *)rte_pktmbuf_prepend(m, sizeof(struct rte_ipv4_hdr));
	if (unlikely(!ipv4_hdr)) {
		DPNODE_LOG_WARNING(node, "No more space in the packet for IPv4 header");
		return VIRTSVC_NEXT_DROP;
	}
	m->packet_type = (m->packet_type & ~RTE_PTYPE_L3_MASK) | RTE_PTYPE_L3_IPV4;

	ipv4_hdr->version_ihl = 0x45;
	ipv4_hdr->total_length = htons(m->pkt_len);
	ipv4_hdr->type_of_service = 0;
	ipv4_hdr->packet_id = packet_id++;
	ipv4_hdr->fragment_offset = 0;
	ipv4_hdr->time_to_live = ttl;
	ipv4_hdr->next_proto_id = proto;
	ipv4_hdr->src_addr = df->virtsvc->virtual_addr;;
	ipv4_hdr->hdr_checksum = 0;
	m->ol_flags |= RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_IP_CKSUM;
	m->tx_offload = 0;
	m->l2_len = sizeof(struct rte_ether_hdr);
	m->l3_len = sizeof(struct rte_ipv4_hdr);

	if (proto == IPPROTO_TCP) {
		tcp_hdr = (struct rte_tcp_hdr *)(ipv4_hdr + 1);

		conn = virtsvc_get_conn_on_port(df->virtsvc, tcp_hdr->dst_port);
		if (!conn->last_pkt_timestamp)
			return VIRTSVC_NEXT_DROP;
		conn->last_pkt_timestamp = rte_get_timer_cycles();
		virtsvc_tcp_state_change(conn, tcp_hdr->tcp_flags);

		tcp_hdr->dst_port = conn->vf_l4_port;
		tcp_hdr->src_port = df->virtsvc->virtual_port;
		tcp_hdr->cksum = 0;
		m->ol_flags |= RTE_MBUF_F_TX_TCP_CKSUM;
		m->l4_len = DP_TCP_HDR_LEN(tcp_hdr);
	} else {
		udp_hdr = (struct rte_udp_hdr *)(ipv4_hdr + 1);

		conn = virtsvc_get_conn_on_port(df->virtsvc, udp_hdr->dst_port);
		if (!conn->last_pkt_timestamp)
			return VIRTSVC_NEXT_DROP;
		conn->last_pkt_timestamp = rte_get_timer_cycles();

		udp_hdr->dst_port = conn->vf_l4_port;
		udp_hdr->src_port = df->virtsvc->virtual_port;
		udp_hdr->dgram_cksum = 0;
		m->ol_flags |= RTE_MBUF_F_TX_UDP_CKSUM;
		m->l4_len = sizeof(struct rte_udp_hdr);
	}

	ipv4_hdr->dst_addr = conn->vf_ip;
	vf_port_id = conn->vf_port_id;
	// to make tx_node work
	df->l3_type = RTE_ETHER_TYPE_IPV4;

	if (dp_port_get_vf_attach_status(vf_port_id) == DP_VF_PORT_DETACHED)
		return VIRTSVC_NEXT_DROP;

	return next_tx_index[vf_port_id];
}

static __rte_always_inline rte_edge_t get_next_index(__rte_unused struct rte_node *node, struct rte_mbuf *m)
{
	struct dp_flow *df = get_dp_flow_ptr(m);

	if (dp_conf_is_offload_enabled())
		DPNODE_LOG_WARNING(node, "Virtual services not supported while offloading");

	if (df->flags.flow_type == DP_FLOW_TYPE_OUTGOING)
		return virtsvc_request_next(node, m, df);
	else if (df->flags.flow_type == DP_FLOW_TYPE_INCOMING)
		return virtsvc_reply_next(node, m, df);

	return VIRTSVC_NEXT_DROP;
}

static uint16_t virtsvc_node_process(struct rte_graph *graph,
								 struct rte_node *node,
								 void **objs,
								 uint16_t nb_objs)
{
	dp_foreach_graph_packet(graph, node, objs, nb_objs, DP_GRAPH_NO_SPECULATED_NODE, get_next_index);
	return nb_objs;
}
