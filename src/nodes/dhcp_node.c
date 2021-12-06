#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_mbuf.h>
#include "node_api.h"
#include "nodes/dhcp_node.h"
#include "dp_mbuf_dyn.h"
#include "dp_lpm.h"

struct dhcp_node_main dhcp_node;
static uint8_t msg_type;

static int dhcp_node_init(const struct rte_graph *graph, struct rte_node *node)
{
	struct dhcp_node_ctx *ctx = (struct dhcp_node_ctx *)node->ctx;

	ctx->next = DHCP_NEXT_DROP;


	RTE_SET_USED(graph);

	return 0;
}

static uint32_t add_dhcp_option(uint8_t *pos, void *value, uint8_t opt, uint8_t size)
{
	uint32_t temp = 0;

	*pos = opt;
	pos++;
	*pos = size;
	pos++;

	if (opt == DP_DHCP_STATIC_ROUT) {
		*pos = 16;
		pos++;
		*pos = 169;
		pos++;
		*pos = 254;
		pos++;
		rte_memcpy(pos, &temp, sizeof(temp));
		pos = pos + sizeof(temp);
		*pos = 0;
		pos++;
		temp = htonl(dp_get_gw_ip4());
		rte_memcpy(pos, &temp, sizeof(temp));
	} else {
		rte_memcpy(pos, value, size);
	}

	return size + 2;
}

static void parse_options(struct dp_dhcp_header *dhcp_pkt, uint16_t tot_op_len){
	uint8_t op;
	uint8_t op_len;
	for(int i = 0; i < tot_op_len; i+= op_len) {
		op = dhcp_pkt->options[i];
		i++;
		op_len = dhcp_pkt->options[i];
		i++;
		switch(op) {
			case DP_DHCP_MSG_TYPE:
				msg_type = dhcp_pkt->options[i];
			break;
			default:
			break;
		}
	}
	return;
}

static __rte_always_inline int handle_dhcp(struct rte_mbuf *m)
{
	struct dp_dhcp_header *dhcp_hdr;
	struct rte_ether_hdr *incoming_eth_hdr;
	struct rte_ipv4_hdr *incoming_ipv4_hdr;
	struct rte_udp_hdr *incoming_udp_hdr;
	uint8_t dhcp_type = DP_DHCP_OFFER;
	uint32_t dhcp_lease = DP_DHCP_INFINITE;
	uint32_t dhcp_srv_ident, net_mask;
	uint8_t vend_pos = 0;
	uint16_t mtu, options_len;

	incoming_eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
	incoming_ipv4_hdr = (struct rte_ipv4_hdr*) (incoming_eth_hdr + 1);
	incoming_udp_hdr = (struct rte_udp_hdr*) (incoming_ipv4_hdr + 1);
	dhcp_hdr = rte_pktmbuf_mtod_offset(m, struct dp_dhcp_header *,
									   sizeof(struct rte_ether_hdr)
									   + sizeof(struct rte_ipv4_hdr)
									   + sizeof(struct rte_udp_hdr));

	
	options_len = rte_pktmbuf_data_len(m) - DHCP_FIXED_LEN - sizeof(struct rte_ether_hdr);
	parse_options(dhcp_hdr, options_len);
	
	m->ol_flags = PKT_TX_IPV4 | PKT_TX_IP_CKSUM | PKT_TX_UDP_CKSUM;
	m->l2_len = sizeof(struct rte_ether_hdr);
	m->l3_len = sizeof(struct rte_ipv4_hdr);
	m->pkt_len = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_udp_hdr) + sizeof(struct dp_dhcp_header);
	m->data_len = m->pkt_len; 
	rte_ether_addr_copy(&incoming_eth_hdr->s_addr, &incoming_eth_hdr->d_addr);

	rte_memcpy(incoming_eth_hdr->s_addr.addr_bytes, dp_get_mac(m->port), 6);
	incoming_ipv4_hdr->src_addr = htonl(dp_get_gw_ip4());
	incoming_ipv4_hdr->dst_addr = htonl(dp_get_dhcp_range_ip4(m->port));
	incoming_ipv4_hdr->hdr_checksum = 0;
	incoming_ipv4_hdr->total_length = htons(sizeof(struct dp_dhcp_header) + 
										    sizeof(struct rte_udp_hdr) + sizeof(struct rte_ipv4_hdr));
	
	incoming_udp_hdr->dgram_len = htons(sizeof(struct dp_dhcp_header) + sizeof(struct rte_udp_hdr));
	incoming_udp_hdr->dst_port =  htons(DP_BOOTP_CLNT_PORT);
	incoming_udp_hdr->src_port =  htons(DP_BOOTP_SRV_PORT);
	incoming_udp_hdr->dgram_cksum = rte_ipv4_phdr_cksum(incoming_ipv4_hdr, m->ol_flags);

	switch(msg_type) {
		case DHCPDISCOVER:
			dhcp_type = DP_DHCP_OFFER;
			break;
		case DHCPREQUEST:
			dhcp_type = DP_DHCP_ACK;
			dp_set_neigh_mac(m->port, &incoming_eth_hdr->s_addr);
			break;
		default:
			return 0;

	}
	dhcp_hdr->op = DP_BOOTP_REPLY;
	dhcp_hdr->yiaddr = htonl(dp_get_dhcp_range_ip4(m->port));
	dhcp_hdr->siaddr  = htonl(dp_get_gw_ip4());
	dhcp_hdr->giaddr = htonl(dp_get_gw_ip4());
	rte_memcpy(dhcp_hdr->chaddr, dp_get_mac(m->port), 6);
	memset(dhcp_hdr->options, 0, sizeof(dhcp_hdr->options));
	dhcp_hdr->magic = htonl(DHCP_MAGIC_COOKIE);

	dhcp_srv_ident = htonl(dp_get_gw_ip4());
	net_mask = htonl(DP_DHCP_MASK);
	mtu = htons(DP_DHCP_MTU_VALUE);

	vend_pos += add_dhcp_option(&dhcp_hdr->options[vend_pos] , &dhcp_type, DP_DHCP_MSG_TYPE, 1);
	vend_pos += add_dhcp_option(&dhcp_hdr->options[vend_pos] , &dhcp_lease, DP_DHCP_LEASE_MSG, 4);
	vend_pos += add_dhcp_option(&dhcp_hdr->options[vend_pos] , &dhcp_srv_ident, DP_DHCP_SRV_IDENT, 4);
	vend_pos += add_dhcp_option(&dhcp_hdr->options[vend_pos] , &dhcp_srv_ident, DP_DHCP_STATIC_ROUT, 12);
	vend_pos += add_dhcp_option(&dhcp_hdr->options[vend_pos] , &net_mask, DP_DHCP_SUBNET_MASK, 4);
	vend_pos += add_dhcp_option(&dhcp_hdr->options[vend_pos] , &mtu, DP_DHCP_MTU, 2);
	//vend_pos += add_dhcp_option(&dhcp_hdr->vend[vend_pos] , &dhcp_srv_ident, DP_DHCP_ROUTER, 4);

	dhcp_hdr->options[vend_pos] = DP_DHCP_END;

	return 1;
} 

static __rte_always_inline uint16_t dhcp_node_process(struct rte_graph *graph,
													 struct rte_node *node,
													 void **objs,
													 uint16_t cnt)
{
	struct rte_mbuf *mbuf0, **pkts;
	int i;

	pkts = (struct rte_mbuf **)objs;


	for (i = 0; i < cnt; i++) {
		mbuf0 = pkts[i];
		if (handle_dhcp(mbuf0))
			rte_node_enqueue_x1(graph, node, dhcp_node.next_index[mbuf0->port] , *objs);
		else
			rte_node_enqueue_x1(graph, node, DHCP_NEXT_DROP, *objs);
		rte_node_enqueue_x1(graph, node, DHCP_NEXT_DROP, *objs);
	}	

    return cnt;
}

int dhcp_set_next(uint16_t port_id, uint16_t next_index)
{

	dhcp_node.next_index[port_id] = next_index;
	return 0;
}

static struct rte_node_register dhcp_node_base = {
	.name = "dhcp",
	.init = dhcp_node_init,
	.process = dhcp_node_process,

	.nb_edges = DHCP_NEXT_MAX,
	.next_nodes =
		{
			[DHCP_NEXT_DROP] = "drop",
		},
};

struct rte_node_register *dhcp_node_get(void)
{
	return &dhcp_node_base;
}

RTE_NODE_REGISTER(dhcp_node_base);
