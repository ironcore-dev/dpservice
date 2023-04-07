#include "nodes/common_node.h"
#include "dp_error.h"
#include "dp_log.h"

#ifdef ENABLE_GRAPHTRACE
#include <rte_ethdev.h>
#include <rte_ip.h>
#include "dp_mbuf_dyn.h"
#include "rte_flow/dp_rte_flow.h"
#include "dp_util.h"

#define PRINT_LAYER(PPOS, BUF, BUFSIZE, FORMAT, ...) do { \
	if (*(PPOS) < (BUFSIZE)) \
		*(PPOS) += snprintf((BUF) + *(PPOS), (BUFSIZE) - *(PPOS), \
					"%s" FORMAT, \
					*(PPOS) ? " / " : "", \
					##__VA_ARGS__); \
} while (0)

static void dp_graphtrace_print_ether(void **p_pkt_data, size_t *p_pos, char *buf, size_t bufsize)
{
	struct rte_ether_hdr *ether_hdr = (struct rte_ether_hdr *)*p_pkt_data;

	PRINT_LAYER(p_pos, buf, bufsize,
		RTE_ETHER_ADDR_PRT_FMT " -> " RTE_ETHER_ADDR_PRT_FMT,
		RTE_ETHER_ADDR_BYTES(&ether_hdr->src_addr), RTE_ETHER_ADDR_BYTES(&ether_hdr->dst_addr));

	*p_pkt_data = ether_hdr + 1;
}

static int dp_graphtrace_print_ipv4(void **p_pkt_data, size_t *p_pos, char *buf, size_t bufsize)
{
	struct rte_ipv4_hdr *ipv4_hdr = (struct rte_ipv4_hdr *)*p_pkt_data;

	PRINT_LAYER(p_pos, buf, bufsize,
		DP_IPV4_PRINT_FMT " -> " DP_IPV4_PRINT_FMT,
		DP_IPV4_PRINT_BYTES(ipv4_hdr->src_addr), DP_IPV4_PRINT_BYTES(ipv4_hdr->dst_addr));

	*p_pkt_data = ipv4_hdr + 1;
	return ipv4_hdr->next_proto_id;
}

static int dp_graphtrace_print_ipv6(void **p_pkt_data, size_t *p_pos, char *buf, size_t bufsize)
{
	struct rte_ipv6_hdr *ipv6_hdr = (struct rte_ipv6_hdr *)*p_pkt_data;

	PRINT_LAYER(p_pos, buf, bufsize,
		DP_IPV6_PRINT_FMT " -> " DP_IPV6_PRINT_FMT,
		DP_IPV6_PRINT_BYTES(ipv6_hdr->src_addr), DP_IPV6_PRINT_BYTES(ipv6_hdr->dst_addr));

	*p_pkt_data = ipv6_hdr + 1;
	return ipv6_hdr->proto;
}

static void dp_graphtrace_print_udp(void **p_pkt_data, size_t *p_pos, char *buf, size_t bufsize)
{
	struct rte_udp_hdr *udp_hdr = (struct rte_udp_hdr *)*p_pkt_data;

	PRINT_LAYER(p_pos, buf, bufsize,
		"UDP %u -> %u len %u",
		ntohs(udp_hdr->src_port), ntohs(udp_hdr->dst_port), ntohs(udp_hdr->dgram_len));

	*p_pkt_data = udp_hdr + 1;
}

static void dp_graphtrace_print_tcp(void **p_pkt_data, size_t *p_pos, char *buf, size_t bufsize)
{
	struct rte_tcp_hdr *tcp_hdr = (struct rte_tcp_hdr *)*p_pkt_data;

	PRINT_LAYER(p_pos, buf, bufsize,
		"TCP %u -> %u seq %u ack %u",
		ntohs(tcp_hdr->src_port), ntohs(tcp_hdr->dst_port), ntohl(tcp_hdr->sent_seq), ntohl(tcp_hdr->recv_ack));

	*p_pkt_data = tcp_hdr + 1;
}

static void dp_graphtrace_print_icmp(void **p_pkt_data, size_t *p_pos, char *buf, size_t bufsize)
{
	struct rte_icmp_hdr *icmp_hdr = (struct rte_icmp_hdr *)*p_pkt_data;

	PRINT_LAYER(p_pos, buf, bufsize,
		"ICMP %u-%u id %u seq %u",
		icmp_hdr->icmp_type, icmp_hdr->icmp_code, ntohs(icmp_hdr->icmp_ident), ntohs(icmp_hdr->icmp_seq_nb));

	*p_pkt_data = icmp_hdr + 1;
}

static inline void dp_graphtrace_print_l4(int proto, void **p_pkt_data, size_t *p_pos, char *buf, size_t bufsize)
{
	if (proto == IPPROTO_UDP)
		dp_graphtrace_print_udp(p_pkt_data, p_pos, buf, bufsize);
	else if (proto == IPPROTO_TCP)
		dp_graphtrace_print_tcp(p_pkt_data, p_pos, buf, bufsize);
	else if (proto == IPPROTO_ICMP || proto == IPPROTO_ICMPV6)
		dp_graphtrace_print_icmp(p_pkt_data, p_pos, buf, bufsize);
}

static void dp_graphtrace_print_pkt(struct rte_mbuf *pkt, char *buf, size_t bufsize)
{
	void *pkt_data = rte_pktmbuf_mtod((struct rte_mbuf *)pkt, void *);
	uint32_t inner_l3_type = pkt->packet_type & RTE_PTYPE_INNER_L3_MASK;
	size_t pos = 0;
	int proto = 0;

	// in case nothing gets printed
	*buf = 0;

	if (pkt->packet_type & RTE_PTYPE_L2_MASK)
		dp_graphtrace_print_ether(&pkt_data, &pos, buf, bufsize);

	if (RTE_ETH_IS_IPV4_HDR(pkt->packet_type))
		proto = dp_graphtrace_print_ipv4(&pkt_data, &pos, buf, bufsize);
	else if (RTE_ETH_IS_IPV6_HDR(pkt->packet_type))
		proto = dp_graphtrace_print_ipv6(&pkt_data, &pos, buf, bufsize);
	else {
		if ((pkt->packet_type & RTE_PTYPE_L4_MASK) == RTE_PTYPE_L4_UDP)
			proto = IPPROTO_UDP;
		else if ((pkt->packet_type & RTE_PTYPE_L4_MASK) == RTE_PTYPE_L4_TCP)
			proto = IPPROTO_TCP;
		else if ((pkt->packet_type & RTE_PTYPE_L4_MASK) == RTE_PTYPE_L4_ICMP)
			proto = IPPROTO_ICMP;
	}

	dp_graphtrace_print_l4(proto, &pkt_data, &pos, buf, bufsize);

	// the inner packet is sometimes not classified as a tunneled packet,
	// so need to look at IPPROTO_IPIP in the header too

	if (pkt->packet_type & RTE_PTYPE_INNER_L2_MASK)
		dp_graphtrace_print_ether(&pkt_data, &pos, buf, bufsize);

	if (proto != IPPROTO_IPIP && (pkt->packet_type & RTE_PTYPE_TUNNEL_MASK) != RTE_PTYPE_TUNNEL_IP)
		return;

	// there is no direct macro for inner types (no shared bit)
	if (proto == IPPROTO_IPIP
		|| inner_l3_type == RTE_PTYPE_INNER_L3_IPV4
		|| inner_l3_type == RTE_PTYPE_INNER_L3_IPV4_EXT
		|| inner_l3_type == RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN
	) {
		proto = dp_graphtrace_print_ipv4(&pkt_data, &pos, buf, bufsize);
	} else if (inner_l3_type == RTE_PTYPE_INNER_L3_IPV6
			|| inner_l3_type == RTE_PTYPE_INNER_L3_IPV6_EXT
			|| inner_l3_type == RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN
	) {
		proto = dp_graphtrace_print_ipv6(&pkt_data, &pos, buf, bufsize);
	} else {
		if ((pkt->packet_type & RTE_PTYPE_INNER_L4_MASK) == RTE_PTYPE_INNER_L4_UDP)
			proto = IPPROTO_UDP;
		else if ((pkt->packet_type & RTE_PTYPE_INNER_L4_MASK) == RTE_PTYPE_INNER_L4_TCP)
			proto = IPPROTO_TCP;
		else if ((pkt->packet_type & RTE_PTYPE_INNER_L4_MASK) == RTE_PTYPE_INNER_L4_ICMP)
			proto = IPPROTO_ICMP;
	}

	dp_graphtrace_print_l4(proto, &pkt_data, &pos, buf, bufsize);
}

// does not use DPNODE_LOG_* due to output alignment
#define GRAPHTRACE_LOG(FORMAT, ...) DP_LOG(INFO, GRAPH, FORMAT, ##__VA_ARGS__)
// shorter lines for debugging
// #define GRAPHTRACE_LOG(FORMAT, ...) printf("GRAPHTRACE: " FORMAT "\n", ##__VA_ARGS__)

#define GRAPHTRACE_PRINT(PKT, FORMAT, ...) do { \
	char _graphtrace_buf[512]; \
	dp_graphtrace_print_pkt((PKT), _graphtrace_buf, sizeof(_graphtrace_buf)); \
	GRAPHTRACE_LOG(FORMAT ": %s", __VA_ARGS__, _graphtrace_buf); \
} while (0)

// TODO: use a unique id (saved in mbuf data)
#define GRAPHTRACE_PKT_ID(PKT) (PKT)

void dp_graphtrace_burst(struct rte_node *node, void **objs, uint16_t nb_objs)
{
	if (dp_conf_get_graphtrace_level() < DP_GRAPHTRACE_LEVEL_NODES)
		return;
	for (uint i = 0; i < nb_objs; ++i)
		GRAPHTRACE_PRINT(objs[i], "%-14s: %p                  ",
						 node->name, GRAPHTRACE_PKT_ID(objs[i]));
}

void dp_graphtrace_burst_next(struct rte_node *node, void **objs, uint16_t nb_objs, rte_edge_t next_index)
{
	if (dp_conf_get_graphtrace_level() < DP_GRAPHTRACE_LEVEL_EDGES)
		return;
	for (uint i = 0; i < nb_objs; ++i)
		GRAPHTRACE_PRINT(objs[i], "%-11s #%u: %p -> %-14s",
						 node->name, i, GRAPHTRACE_PKT_ID(objs[i]), node->nodes[next_index]->name);
}

void dp_graphtrace_burst_tx(struct rte_node *node, void **objs, uint16_t nb_objs, uint16_t port_id)
{
	if (dp_conf_get_graphtrace_level() < DP_GRAPHTRACE_LEVEL_EDGES)
		return;
	for (uint i = 0; i < nb_objs; ++i)
		GRAPHTRACE_PRINT(objs[i], "%-11s #%u: %p >> PORT %-9u",
						 node->name, i, GRAPHTRACE_PKT_ID(objs[i]), port_id);
}

void dp_graphtrace(struct rte_node *node, void *obj)
{
	if (dp_conf_get_graphtrace_level() < DP_GRAPHTRACE_LEVEL_NODES)
		return;
	GRAPHTRACE_PRINT(obj, "%-14s: %p                  ",
					 node->name, GRAPHTRACE_PKT_ID(obj));
}

void dp_graphtrace_next(struct rte_node *node, void *obj, rte_edge_t next_index)
{
	if (dp_conf_get_graphtrace_level() < DP_GRAPHTRACE_LEVEL_EDGES)
		return;
	GRAPHTRACE_PRINT(obj, "%-14s: %p -> %-14s",
					 node->name, GRAPHTRACE_PKT_ID(obj), node->nodes[next_index]->name);
}

#endif /* ENABLE_GRAPHTRACE */


int dp_node_append_tx(struct rte_node_register *node,
					  uint16_t next_tx_indices[DP_MAX_PORTS],
					  uint16_t port_id,
					  const char *tx_node_name)
{
	const char *append_array[] = { tx_node_name };
	rte_edge_t count;

	if (port_id >= DP_MAX_PORTS) {
		DPNODE_LOG_ERR(node, "Port id %u too big, max %u", port_id, DP_MAX_PORTS);
		return DP_ERROR;
	}

	if (rte_node_edge_update(node->id, RTE_EDGE_ID_INVALID, append_array, 1) != 1) {
		DPNODE_LOG_ERR(node, "Cannot add Tx edge to %s", tx_node_name);
		return DP_ERROR;
	}

	count = rte_node_edge_count(node->id);
	if (count <= 0) {
		DPNODE_LOG_ERR(node, "No Tx edge added to %s", tx_node_name);
		return DP_ERROR;
	}

	next_tx_indices[port_id] = count - 1;
	return DP_OK;
}

int dp_node_append_vf_tx(struct rte_node_register *node,
					  uint16_t next_tx_indices[DP_MAX_PORTS],
					  uint16_t port_id,
					  const char *tx_node_name)
{
	if (dp_port_is_pf(port_id)) {
		DPNODE_LOG_ERR(node, "Node not designed to be connected to physical ports");
		return DP_ERROR;
	}
	return dp_node_append_tx(node, next_tx_indices, port_id, tx_node_name);
}


int dp_node_append_pf_tx(struct rte_node_register *node,
					  uint16_t next_tx_indices[DP_MAX_PORTS],
					  uint16_t port_id,
					  const char *tx_node_name)
{
	if (!dp_port_is_pf(port_id)) {
		DPNODE_LOG_ERR(node, "Node not designed to be connected to virtual ports");
		return DP_ERROR;
	}
	return dp_node_append_tx(node, next_tx_indices, port_id, tx_node_name);
}
