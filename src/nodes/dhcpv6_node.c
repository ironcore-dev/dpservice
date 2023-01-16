#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_mbuf.h>
#include "node_api.h"
#include "nodes/common_node.h"
#include "nodes/dhcpv6_node.h"
#include "dp_mbuf_dyn.h"
#include "dp_lpm.h"
#include "dp_log.h"


struct dhcpv6_node_main dhcpv6_node;
static struct client_id cid;
static struct server_id  sid;
static struct ia_option recv_ia;
static struct rapid_commit rapid;
uint8_t client_id_len;

void parse_options(struct dhcpv6_packet* dhcp_pkt, uint8_t len) {
	uint16_t op_id;
	uint16_t op_len;
	//printf("op_0:%d, op_1:%d\n", dhcp_pkt->options[0], dhcp_pkt->options[1]);
	for ( int i = 0; i < len; i += op_len) {
		op_id = (dhcp_pkt->options[i]<<8) + (dhcp_pkt->options[i+1]&0x00ff);
		i = i+2;
		op_len = (dhcp_pkt->options[i]<<8) + (dhcp_pkt->options[i+1]&0x00ff);
		i = i+2;
		if(op_id == DP_CLIENTID) {
			cid.op = htons(op_id);
			cid.len = htons(op_len);
			client_id_len = op_len+4;
			rte_memcpy(&cid.id,&dhcp_pkt->options[i], op_len);
		}	else if ( op_id == DP_IA_NA ) {
				rte_memcpy(&recv_ia.val, &dhcp_pkt->options[i], op_len);
		}	else if ( op_id == DP_RAPID_COMMIT) {
				rapid.op = htons(op_id);
				rapid.len = htons(op_len);
		}
	}
}

void prepare_ia_option(uint16_t port_id)
{
	recv_ia.op = htons(DP_IA_NA);
	recv_ia.len = htons(sizeof(struct ia));
	recv_ia.val.time_1 = INFINITY;
	recv_ia.val.time_2 = INFINITY;

	recv_ia.val.addrv6.op = htons(DP_IAADDR);
	recv_ia.val.addrv6.len = htons(sizeof(struct ia_addr));
	recv_ia.val.addrv6.addr.time_1 = INFINITY;
	recv_ia.val.addrv6.addr.time_2 = INFINITY;
	rte_memcpy(recv_ia.val.addrv6.addr.in6_addr, dp_get_dhcp_range_ip6(port_id), 16);

	recv_ia.val.addrv6.addr.code.op = htons(DP_STATUS_CODE);
	recv_ia.val.addrv6.addr.code.len = htons(2);
	recv_ia.val.addrv6.addr.code.status = STATUS_Success;
	return;
}

static int dhcpv6_node_init(const struct rte_graph *graph, struct rte_node *node)
{
	struct dhcpv6_node_ctx *ctx = (struct dhcpv6_node_ctx *)node->ctx;

	ctx->next = DHCPV6_NEXT_DROP;

	RTE_SET_USED(graph);

	return 0;
}

static __rte_always_inline rte_edge_t get_next_index(struct rte_node *node, struct rte_mbuf *m)
{
	struct rte_ether_hdr *req_eth_hdr;
	struct rte_ipv6_hdr *req_ipv6_hdr; 
	struct rte_udp_hdr *req_udp_hdr;
	struct dhcpv6_packet *dhcp_pkt;
	uint8_t type, recv_len, options_len;
	uint8_t* own_ip6 = dp_get_gw_ip6(m->port);
	uint8_t offset = 0;
	uint8_t index = 0;

	req_eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
	req_ipv6_hdr = (struct rte_ipv6_hdr*) (req_eth_hdr + 1);
	req_udp_hdr = (struct rte_udp_hdr*) (req_ipv6_hdr + 1);
	dhcp_pkt = (struct dhcpv6_packet*) (req_udp_hdr + 1);

	type = dhcp_pkt->msg_type;
	recv_len = rte_pktmbuf_data_len(m);
	options_len = recv_len -  DHCPV6_FIXED_LEN - sizeof(struct rte_ether_hdr) - sizeof(struct rte_ipv6_hdr ) - sizeof(struct rte_udp_hdr);

	parse_options(dhcp_pkt, options_len);
	rte_ether_addr_copy(&req_eth_hdr->src_addr, &req_eth_hdr->dst_addr);
	rte_memcpy(req_eth_hdr->src_addr.addr_bytes, dp_get_mac(m->port), 6);

	rte_memcpy(req_ipv6_hdr->dst_addr, req_ipv6_hdr->src_addr,sizeof(req_ipv6_hdr->dst_addr));
	rte_memcpy(req_ipv6_hdr->src_addr, own_ip6,sizeof(req_ipv6_hdr->src_addr));
	req_udp_hdr->src_port = htons(DHCPV6_SERVER_PORT);
	req_udp_hdr->dst_port = htons(DHCPV6_CLIENT_PORT);
	req_udp_hdr->dgram_cksum = 0;

	switch(type) {
		case DHCPV6_SOLICIT:
			dhcp_pkt->msg_type = DHCPV6_ADVERTISE;
			offset = client_id_len + sizeof(struct server_id) + sizeof(struct ia_option) +sizeof(struct rapid_commit);
			break;

		case DHCPV6_REQUEST:
			dhcp_pkt->msg_type = DHCPV6_REPLY;
			offset = client_id_len + sizeof(struct server_id) + sizeof(struct ia_option) +sizeof(struct rapid_commit);
			break;

		case DHCPV6_CONFIRM:
			dhcp_pkt->msg_type = DHCPV6_REPLY;
			break;

		default:
			return DHCPV6_NEXT_DROP;
	}
	sid.op = htons(DP_SERVERID);
	sid.len = htons(sizeof(struct duid_t));
	sid.id.type = htons(DP_DUID_LL);
	sid.id.hw_type = htons(DP_DUMMY_HW_ID);
	rte_ether_addr_copy(&req_eth_hdr->dst_addr, &sid.id.mac);

	prepare_ia_option(m->port);

	if(offset >= options_len) {
		if (!rte_pktmbuf_append(m, offset - options_len)) {
			DPNODE_LOG_WARNING(node, "Not enough space for DHCPv6 options in packet");
			return DHCPV6_NEXT_DROP;
		}
	} else {
		rte_pktmbuf_trim(m, options_len-offset);
	}	
	rte_memcpy(&dhcp_pkt->options[index], &rapid, sizeof(struct rapid_commit));
	index+=sizeof(struct rapid_commit);
	rte_memcpy(&dhcp_pkt->options[index], &cid, client_id_len);
	index += client_id_len;
	rte_memcpy(&dhcp_pkt->options[index], &sid, sizeof(struct server_id));
	index+=sizeof(struct server_id);
	rte_memcpy(&dhcp_pkt->options[index], &recv_ia,sizeof(struct ia_option));

	req_ipv6_hdr->payload_len = htons(offset +  DHCPV6_FIXED_LEN + DP_UDP_HDR_SZ);
	req_udp_hdr->dgram_len = htons(offset + DHCPV6_FIXED_LEN + DP_UDP_HDR_SZ);
	req_udp_hdr->dgram_cksum = rte_ipv6_udptcp_cksum(req_ipv6_hdr,req_udp_hdr);

	return dhcpv6_node.next_index[m->port];
}

static uint16_t dhcpv6_node_process(struct rte_graph *graph,
									struct rte_node *node,
									void **objs,
									uint16_t nb_objs)
{
	dp_foreach_graph_packet(graph, node, objs, nb_objs, get_next_index);
	return nb_objs;
}

int dhcpv6_set_next(uint16_t port_id, uint16_t next_index)
{
	dhcpv6_node.next_index[port_id] = next_index;
	return 0;
}

static struct rte_node_register dhcpv6_node_base = {
	.name = "dhcpv6",
	.init = dhcpv6_node_init,
	.process = dhcpv6_node_process,

	.nb_edges = DHCPV6_NEXT_MAX,
	.next_nodes =
		{
			[DHCPV6_NEXT_DROP] = "drop",
		},
};

struct rte_node_register *dhcpv6_node_get(void)
{
	return &dhcpv6_node_base;
}

RTE_NODE_REGISTER(dhcpv6_node_base);
