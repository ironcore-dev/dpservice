#define _GNU_SOURCE
#include <string.h>  // need memmem()

#include "nodes/dhcp_node.h"
#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_mbuf.h>
#include "dp_conf.h"
#include "dp_error.h"
#include "dp_log.h"
#include "dp_lpm.h"
#include "dp_vm.h"
#include "nodes/common_node.h"

DP_NODE_REGISTER(DHCP, dhcp, DP_NODE_DEFAULT_NEXT_ONLY);

static uint16_t next_tx_index[DP_MAX_PORTS];

int dhcp_node_append_vf_tx(uint16_t port_id, const char *tx_node_name)
{
	return dp_node_append_vf_tx(DP_NODE_GET_SELF(dhcp), next_tx_index, port_id, tx_node_name);
}

// constant after init, precompute them
static uint32_t dhcp_lease = DP_DHCP_INFINITE;
static rte_be32_t server_ip;
static uint32_t net_mask = DP_DHCP_MASK_NL;
static rte_be16_t iface_mtu;
static rte_be16_t udp_hdr_dst_port;
static rte_be16_t udp_hdr_src_port;
static rte_be32_t dhcp_hdr_magic;

// list of (mask/address -> address):
//   169.254.0.0/16 -> 0.0.0.0
//   0.0.0.0/0 -> server_ip
static const uint8_t classless_route_prefix[] = { 16, 169, 254, 0, 0, 0, 0, 0 };
#ifndef ENABLE_VIRTSVC
static uint8_t classless_route[sizeof(classless_route_prefix) + sizeof(server_ip)];
#else
// add route for virtual services residing in link-local space
//   169.254.1.0/24 -> server_ip
static const uint8_t virtsvc_route_prefix[] = { 24, 169, 254, 1 };
static uint8_t classless_route[sizeof(classless_route_prefix) + sizeof(server_ip) + sizeof(virtsvc_route_prefix) + sizeof(server_ip)];
static_assert(DP_VIRTSVC_MAX <= UINT8_MAX+1, "Number of virtual services can be higher than supported link-local subnet size");
#endif


static int dhcp_node_init(__rte_unused const struct rte_graph *graph, __rte_unused struct rte_node *node)
{
	server_ip = htonl(dp_get_gw_ip4());
	iface_mtu = htons(dp_conf_get_dhcp_mtu());

	dhcp_hdr_magic = htonl(DHCP_MAGIC_COOKIE);

	udp_hdr_dst_port = htons(DP_BOOTP_CLI_PORT);
	udp_hdr_src_port = htons(DP_BOOTP_SRV_PORT);

	rte_memcpy(classless_route, classless_route_prefix, sizeof(classless_route_prefix));
	rte_memcpy(classless_route+sizeof(classless_route_prefix), &server_ip, sizeof(server_ip));
#ifdef ENABLE_VIRTSVC
	rte_memcpy(classless_route+sizeof(classless_route_prefix) + sizeof(server_ip), virtsvc_route_prefix, sizeof(virtsvc_route_prefix));
	rte_memcpy(classless_route+sizeof(classless_route_prefix) + sizeof(server_ip) + sizeof(virtsvc_route_prefix), &server_ip, sizeof(server_ip));
#endif

	return DP_OK;
}

static __rte_always_inline int add_dhcp_option(uint8_t **pos_ptr, uint8_t *end, uint8_t opt, const void *value, uint8_t size)
{
	uint8_t *pos = *pos_ptr;

	if (pos + 2 + size >= end)
		return DP_ERROR;

	*pos++ = opt;
	*pos++ = size;
	rte_memcpy(pos, value, size);
	*pos_ptr += 2 + size;
	return DP_OK;
}

/** @return size of generated options or error */
static __rte_always_inline int add_dhcp_options(struct dp_dhcp_header *dhcp_hdr,
												 uint8_t msg_type,
												 enum dp_pxe_mode pxe_mode)
{
	uint8_t *pos = dhcp_hdr->options;
	uint8_t *end = pos + DHCP_MAX_OPTIONS_LEN;
	const struct dp_conf_dhcp_dns *dhcp_dns = dp_conf_get_dhcp_dns();

	if (DP_FAILED(add_dhcp_option(&pos, end, DHCP_OPT_MESSAGE_TYPE, &msg_type, sizeof(msg_type)))
		|| DP_FAILED(add_dhcp_option(&pos, end, DHCP_OPT_IP_LEASE_TIME, &dhcp_lease, sizeof(dhcp_lease)))
		|| DP_FAILED(add_dhcp_option(&pos, end, DHCP_OPT_SERVER_ID, &server_ip, sizeof(server_ip)))
		|| DP_FAILED(add_dhcp_option(&pos, end, DHCP_OPT_CLASSLESS_ROUTE, &classless_route, sizeof(classless_route)))
		|| DP_FAILED(add_dhcp_option(&pos, end, DHCP_OPT_SUBNET_MASK, &net_mask, sizeof(net_mask)))
		|| DP_FAILED(add_dhcp_option(&pos, end, DHCP_OPT_INTERFACE_MTU, &iface_mtu, sizeof(iface_mtu)))
	)
		return DP_ERROR;

	if (pxe_mode != DP_PXE_MODE_NONE)
		if (DP_FAILED(add_dhcp_option(&pos, end, DHCP_OPT_ROUTER, &server_ip, sizeof(server_ip))))
			return DP_ERROR;

	if (dhcp_dns->len)
		if (DP_FAILED(add_dhcp_option(&pos, end, DHCP_OPT_DNS, dhcp_dns->array, dhcp_dns->len)))
			return DP_ERROR;

	if (pos >= end)
		return DP_ERROR;
	*pos++ = DHCP_OPT_END;

	return pos - dhcp_hdr->options;
}

static int parse_options(struct dp_dhcp_header *dhcp_pkt,
						 int options_len,
						 uint8_t *msg_type,
						 enum dp_pxe_mode *pxe_mode)
{
	uint8_t op_type;
	uint8_t op_len = 0;
	int result = DP_ERROR;  // need at least msg_type

	for (int i = 0; i < options_len; i += op_len) {
		op_type = dhcp_pkt->options[i++];
		if (op_type == DHCP_OPT_PAD)
			continue;
		if (op_type == DHCP_OPT_END)
			break;
		if (i >= options_len) {
			DPS_LOG_WARNING("Malformed DHCP option");
			return DP_ERROR;
		}
		op_len = dhcp_pkt->options[i++];
		if (i + op_len > options_len) {
			DPS_LOG_WARNING("Malformed DHCP option");
			return DP_ERROR;
		}
		switch (op_type) {
		case DHCP_OPT_MESSAGE_TYPE:
			*msg_type = dhcp_pkt->options[i];
			result = DP_OK;
			break;
		case DHCP_OPT_USER_CLASS:
			if (op_len == DP_USER_CLASS_INF_LEN
				&& !memcmp(&dhcp_pkt->options[i], DP_USER_CLASS_INF_COMP_STR, DP_USER_CLASS_INF_LEN)
			)
				*pxe_mode = DP_PXE_MODE_HTTP;
			break;
		case DHCP_OPT_VENDOR_CLASS_ID:
			if (op_len >= DP_VND_CLASS_ID_LEN
				&& memmem(&dhcp_pkt->options[i], op_len, DP_VND_CLASS_ID_COMP_STR, DP_VND_CLASS_ID_LEN)
			)
				*pxe_mode = DP_PXE_MODE_TFTP;
			break;
		default:
			break;
		}
	}
	return result;
}

static __rte_always_inline rte_edge_t get_next_index(struct rte_node *node, struct rte_mbuf *m)
{
	struct rte_ether_hdr *incoming_eth_hdr;
	struct rte_ipv4_hdr *incoming_ipv4_hdr;
	struct rte_udp_hdr *incoming_udp_hdr;
	struct dp_dhcp_header *dhcp_hdr;
	struct dp_port *port = dp_get_port(m);
	int options_len, header_size;
	uint8_t msg_type;

	// TODO(gg): Once PXE is tested, possibly remove 'static' if not needed
	static enum dp_pxe_mode pxe_mode = DP_PXE_MODE_NONE;
	rte_be32_t pxe_srv_ip;
	char pxe_srv_ip_str[INET_ADDRSTRLEN];
	uint8_t response_type;

	incoming_eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
	incoming_ipv4_hdr = (struct rte_ipv4_hdr *)(incoming_eth_hdr + 1);
	incoming_udp_hdr = (struct rte_udp_hdr *)(incoming_ipv4_hdr + 1);
	dhcp_hdr = (struct dp_dhcp_header *)(incoming_udp_hdr + 1);
	options_len = rte_pktmbuf_data_len(m)
					- ((uint8_t *)dhcp_hdr - (uint8_t *)incoming_eth_hdr)
					- offsetof(struct dp_dhcp_header, options);

	if (dhcp_hdr->op != DP_BOOTP_REQUEST) {
		DPNODE_LOG_WARNING(node, "Not a DHCP request", DP_LOG_VALUE(dhcp_hdr->op));
		return DHCP_NEXT_DROP;
	}

	if (DP_FAILED(parse_options(dhcp_hdr, options_len, &msg_type, &pxe_mode))) {
		DPNODE_LOG_WARNING(node, "Invalid DHCP packet received");
		return DHCP_NEXT_DROP;
	}

	if (msg_type == DHCPDISCOVER) {
		response_type = DHCPOFFER;
	} else if (msg_type == DHCPREQUEST) {
		response_type = DHCPACK;
	} else {
		// unhandled by design
		DPNODE_LOG_DEBUG(node, "Unhandled DHCP message type", DP_LOG_VALUE(msg_type));
		return DHCP_NEXT_DROP;
	}

	/* rewrite the packet and send it back as a response */

	m->ol_flags = RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_IP_CKSUM | RTE_MBUF_F_TX_UDP_CKSUM;
	m->tx_offload = 0;
	m->l2_len = sizeof(struct rte_ether_hdr);
	m->l3_len = sizeof(struct rte_ipv4_hdr);
	m->l4_len = sizeof(struct rte_udp_hdr);

	rte_ether_addr_copy(&incoming_eth_hdr->src_addr, &incoming_eth_hdr->dst_addr);
	rte_ether_addr_copy(&port->vm.info.own_mac, &incoming_eth_hdr->src_addr);
	if (response_type == DHCPACK)
		rte_ether_addr_copy(&incoming_eth_hdr->dst_addr, &port->vm.info.neigh_mac);

	incoming_ipv4_hdr->src_addr = server_ip;

	incoming_udp_hdr->dst_port = udp_hdr_dst_port;
	incoming_udp_hdr->src_port = udp_hdr_src_port;

	dhcp_hdr->op = DP_BOOTP_REPLY;
	dhcp_hdr->magic = dhcp_hdr_magic;
	dhcp_hdr->yiaddr = htonl(port->vm.info.own_ip);
	dhcp_hdr->giaddr = server_ip;
	rte_memcpy(dhcp_hdr->chaddr, incoming_eth_hdr->dst_addr.addr_bytes, 6);

	if (pxe_mode != DP_PXE_MODE_NONE) {
		memset(&incoming_eth_hdr->dst_addr, ~0, sizeof(incoming_eth_hdr->dst_addr));
		incoming_ipv4_hdr->dst_addr = 0xFFFFFFFF;
		pxe_srv_ip = htonl(port->vm.info.pxe_ip);
		dhcp_hdr->siaddr = pxe_srv_ip;
		switch (pxe_mode) {
		case DP_PXE_MODE_TFTP:
			snprintf(dhcp_hdr->file, sizeof(dhcp_hdr->file), "%s", DP_PXE_TFTP_PATH);
			break;
		case DP_PXE_MODE_HTTP:
			if (!inet_ntop(AF_INET, &pxe_srv_ip, pxe_srv_ip_str, INET_ADDRSTRLEN)) {
				DPNODE_LOG_WARNING(node, "Cannot convert PXE server IP",
								   DP_LOG_IPV4(ntohl(pxe_srv_ip)), DP_LOG_RET(errno));
				return DHCP_NEXT_DROP;
			}
			snprintf(dhcp_hdr->file, sizeof(dhcp_hdr->file), "%s%s%s",
					"http://", pxe_srv_ip_str, port->vm.info.pxe_str);
			break;
		case DP_PXE_MODE_NONE:
			assert(false);
		}
	} else {
		incoming_ipv4_hdr->dst_addr = htonl(port->vm.info.own_ip);
		dhcp_hdr->siaddr = server_ip;
	}

	options_len = add_dhcp_options(dhcp_hdr, response_type, pxe_mode);
	if (DP_FAILED(options_len)) {
		DPNODE_LOG_WARNING(node, "DHCP response options too large for a packet");
		return DHCP_NEXT_DROP;
	}

	// packet length changed because of new options, recompute envelopes
	header_size = offsetof(struct dp_dhcp_header, options) + options_len;
	incoming_ipv4_hdr->hdr_checksum = 0;
	incoming_ipv4_hdr->total_length = htons(sizeof(struct rte_ipv4_hdr)
											+ sizeof(struct rte_udp_hdr)
											+ header_size);
	incoming_udp_hdr->dgram_len = htons(sizeof(struct rte_udp_hdr) + header_size);
	incoming_udp_hdr->dgram_cksum = 0;
	m->pkt_len = sizeof(struct rte_ether_hdr)
				 + sizeof(struct rte_ipv4_hdr)
				 + sizeof(struct rte_udp_hdr)
				 + header_size;
	m->data_len = m->pkt_len;

	return next_tx_index[m->port];
}

static uint16_t dhcp_node_process(struct rte_graph *graph,
								  struct rte_node *node,
								  void **objs,
								  uint16_t nb_objs)
{
	dp_foreach_graph_packet(graph, node, objs, nb_objs, DP_GRAPH_NO_SPECULATED_NODE, get_next_index);
	return nb_objs;
}
