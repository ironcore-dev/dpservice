// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#define _GNU_SOURCE
#include <string.h>  // need memmem()

#include "nodes/dhcpv6_node.h"
#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_mbuf.h>
#include "dp_error.h"
#include "dp_log.h"
#include "dp_lpm.h"
#include "dp_iface.h"
#include "nodes/common_node.h"
#include "protocols/dp_dhcpv6.h"

#define DP_DHCPV6_HDR_FIXED_LEN offsetof(struct dhcpv6_packet, options)
#define DP_DHCPV6_PKT_FIXED_LEN (sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv6_hdr) + sizeof(struct rte_udp_hdr) + DP_DHCPV6_HDR_FIXED_LEN)

// this can be anything, IANA defined values do exist, but are not applicable here
#define DP_DHCPV6_HW_ID	0xabcd

struct dp_dhcpv6_reply_options {
	int opt_iana_len;
	struct dhcpv6_opt_ia_na_single_addr_status opt_iana;
	int opt_cid_len;
	struct dhcpv6_opt_client_id opt_cid;
	int opt_boot_file_len;
	struct dhcpv6_opt_boot_file_url boot_file_url;
	enum dp_pxe_mode pxe_mode;
	int opt_rapid_len;
	struct dhcpv6_option opt_rapid;
};


DP_NODE_REGISTER(DHCPV6, dhcpv6, DP_NODE_DEFAULT_NEXT_ONLY);

static uint16_t next_tx_index[DP_MAX_PORTS];

int dhcpv6_node_append_vf_tx(uint16_t port_id, const char *tx_node_name)
{
	return dp_node_append_vf_tx(DP_NODE_GET_SELF(dhcpv6), next_tx_index, port_id, tx_node_name);
}


// constant after init
static const union dp_ipv6 *own_ip6;
static struct dhcpv6_opt_server_id_ll opt_sid_template;
static struct dhcpv6_opt_ia_na_single_addr_status opt_iana_template;

static int dhcpv6_node_init(__rte_unused const struct rte_graph *graph, __rte_unused struct rte_node *node)
{
	own_ip6 = dp_get_gw_ip6();

	opt_sid_template.op_code = htons(DHCPV6_OPT_SERVERID);
	opt_sid_template.op_len = htons(sizeof(struct dhcpv6_duid_ll));
	opt_sid_template.id.type = htons(DHCPV6_DUID_LL);
	opt_sid_template.id.hw_type = htons(DP_DHCPV6_HW_ID);
	// id.mac will be filled in later based on the used port

	opt_iana_template.op_code = htons(DHCPV6_OPT_IA_NA);
	opt_iana_template.op_len = htons(sizeof(struct dhcpv6_ia_na_single_addr_status));
	// ia_na.iaid will be filled-in later based on the client request
	opt_iana_template.ia_na.t1 = DHCPV6_INFINITY;
	opt_iana_template.ia_na.t2 = DHCPV6_INFINITY;
	opt_iana_template.ia_na.options[0].op_code = htons(DHCPV6_OPT_IAADDR);
	opt_iana_template.ia_na.options[0].op_len = htons(sizeof(struct dhcpv6_ia_addr_status));
	// addr.ipv6 will be filled in later based on the used port
	opt_iana_template.ia_na.options[0].addr.preferred_lifetime = DHCPV6_INFINITY;
	opt_iana_template.ia_na.options[0].addr.valid_lifetime = DHCPV6_INFINITY;
	opt_iana_template.ia_na.options[0].addr.options[0].op_code = htons(DHCPV6_OPT_STATUS_CODE);
	opt_iana_template.ia_na.options[0].addr.options[0].op_len = htons(sizeof(uint16_t));
	opt_iana_template.ia_na.options[0].addr.options[0].status = DHCPV6_STATUS_SUCCESS;

	return DP_OK;
}

static void dp_fill_boot_file_option(struct dp_dhcpv6_reply_options *reply_options,
									 const enum dp_pxe_mode MODE, const char *suffix,
									 const struct dp_port *port)
{
	char ipv6_str[INET6_ADDRSTRLEN];
	uint16_t url_len;

	reply_options->pxe_mode = MODE;
	reply_options->boot_file_url.op_code = htons(DHCPV6_OPT_BOOT_FILE);
	assert(port->iface.cfg.pxe_ip.is_v6);
	DP_IPADDR_TO_STR(&port->iface.cfg.pxe_ip, ipv6_str);

	if (MODE == DP_PXE_MODE_TFTP)
		url_len = (uint16_t)snprintf(reply_options->boot_file_url.boot_file_url, DHCPV6_BOOT_FILE_BUF_LEN,
										"tftp://[%s]/%s", ipv6_str, suffix);
	else if (MODE == DP_PXE_MODE_HTTP)
		url_len = (uint16_t)snprintf(reply_options->boot_file_url.boot_file_url, DHCPV6_BOOT_FILE_BUF_LEN,
										"http://[%s]/%s", ipv6_str, suffix);
	else
		assert(false);

	reply_options->boot_file_url.op_len = htons(url_len);
	reply_options->opt_boot_file_len = (int)sizeof(reply_options->boot_file_url.op_code) +
										(int)sizeof(reply_options->boot_file_url.op_len) + url_len;
}


static __rte_always_inline int parse_options(struct rte_mbuf *m,
											 const uint8_t *options,
											 size_t options_len,
											 struct dp_dhcpv6_reply_options *reply_options)
{
	uint16_t op_code;
	uint16_t op_len = 0;
	const struct dhcpv6_option *opt;
	const struct dhcpv6_opt_vnd_cls *opt_vnd;
	const struct dhcpv6_opt_usr_cls *opt_usr;
	struct dp_port *port = dp_get_in_port(m);

	for (size_t i = 0;
		 i + sizeof(struct dhcpv6_option) < (size_t)options_len;  // len already checked for being positive
		 i += sizeof(struct dhcpv6_option) + op_len
	) {
		opt = (const struct dhcpv6_option *)&options[i];
		op_code = ntohs(opt->op_code);
		op_len = ntohs(opt->op_len);
		if (i + op_len > options_len) {
			DPS_LOG_WARNING("Malformed DHCPv6 option", DP_LOG_VALUE(op_code));
			return DP_ERROR;
		}
		switch (op_code) {
		case DHCPV6_OPT_CLIENTID:
			if (op_len > sizeof(reply_options->opt_cid.id)) {
				DPS_LOG_WARNING("Malformed DHCPv6 CLIENTID option");
				return DP_ERROR;
			}
			reply_options->opt_cid.op_code = opt->op_code;
			reply_options->opt_cid.op_len = opt->op_len;
			rte_memcpy(&reply_options->opt_cid.id, &opt->data, op_len);
			reply_options->opt_cid_len = op_len + 4;
			break;
		case DHCPV6_OPT_IA_NA:
			// we only need the ID from this option, no need to iterate the sub-options for now
			if (op_len < sizeof(struct dhcpv6_ia_na)) {
				DPS_LOG_WARNING("Malformed DHCPv6 IA_NA option");
				return DP_ERROR;
			}
			reply_options->opt_iana = opt_iana_template;
			reply_options->opt_iana.ia_na.iaid = ((const struct dhcpv6_ia_na *)&opt->data)->iaid;
			// cannot use optimized function here due to the destination being packed (can cause alignment problems)
			static_assert(sizeof(reply_options->opt_iana.ia_na.options[0].addr.ipv6) == sizeof(dp_get_in_port(m)->iface.cfg.dhcp_ipv6.bytes),
						  "Incompatible IPv6 array for IA_NA options");
			rte_memcpy(reply_options->opt_iana.ia_na.options[0].addr.ipv6,
					   dp_get_in_port(m)->iface.cfg.dhcp_ipv6.bytes, sizeof(dp_get_in_port(m)->iface.cfg.dhcp_ipv6.bytes));
			reply_options->opt_iana_len = sizeof(opt_iana_template);
			break;
		case DHCPV6_OPT_RAPID_COMMIT:
			if (op_len != 0) {
				DPS_LOG_WARNING("Invalid DHCPv6 rapid commit option");
				return DP_ERROR;
			}
			reply_options->opt_rapid.op_code = opt->op_code;
			reply_options->opt_rapid.op_len = 0;
			reply_options->opt_rapid_len = sizeof(struct dhcpv6_option);
			break;
		case DHCPV6_OPT_VENDOR_CLASS:
			opt_vnd = (const struct dhcpv6_opt_vnd_cls *)opt;
			if (opt_vnd->opq_data_len >= DP_VND_CLASS_ID_LEN
				&& memmem(opt_vnd->opq_data, op_len, DP_VND_CLASS_ID_COMP_STR, DP_VND_CLASS_ID_LEN)
			)
				dp_fill_boot_file_option(reply_options, DP_PXE_MODE_TFTP, DP_PXE_TFTP_PATH, port);
			break;

		case DHCPV6_OPT_USER_CLASS:
			opt_usr = (const struct dhcpv6_opt_usr_cls *)opt;
			if (ntohs(opt_usr->sub_opt_len) == DP_USER_CLASS_INF_LEN
				&& !memcmp(opt_usr->sub_opt_data, DP_USER_CLASS_INF_COMP_STR, DP_USER_CLASS_INF_LEN)
			)
				dp_fill_boot_file_option(reply_options, DP_PXE_MODE_HTTP, port->iface.cfg.pxe_str, port);
			break;
		default:
			break;
		}
	}
	return DP_OK;
}

static __rte_always_inline int resize_packet(struct rte_mbuf *m, int delta)
{
	if (delta > 0) {
		if (delta > UINT16_MAX || !rte_pktmbuf_append(m, (uint16_t)delta)) {
			DPS_LOG_WARNING("Not enough space for DHCPv6 options in packet");
			return DP_ERROR;
		}
	} else if (delta < 0) {
		if (delta < -UINT16_MAX || DP_FAILED(rte_pktmbuf_trim(m, (uint16_t)(-delta)))) {
			DPS_LOG_WARNING("Invalid trim of DHCPv6 packet", DP_LOG_VALUE(-delta));
			return DP_ERROR;
		}
	}
	return DP_OK;
}

static __rte_always_inline int strip_options(struct rte_mbuf *m, int options_len)
{
	if (DP_FAILED(resize_packet(m, -options_len)))
		return DP_ERROR;
	return 0;
}

/** @return size of generated options or error */
static int generate_reply_options(struct rte_mbuf *m, uint8_t *options, int options_len)
{
	int reply_options_len;
	struct dhcpv6_opt_server_id_ll opt_sid;
	struct dhcpv6_opt_dns_servers dns_opt;
	struct dp_dhcpv6_reply_options reply_options = {0};  // this makes *_len fields 0, needed later
	const struct dp_conf_dhcp_dns *dhcpv6_dns = dp_conf_get_dhcpv6_dns();

	if (DP_FAILED(parse_options(m, options, options_len, &reply_options))) {
		DPS_LOG_WARNING("Invalid DHCPv6 options received");
		return DP_ERROR;
	}

	dns_opt.opt_code = htons(DHCPV6_OPT_DNS);
	dns_opt.opt_len = htons(dhcpv6_dns->len);

	opt_sid = opt_sid_template;
	rte_ether_addr_copy(&rte_pktmbuf_mtod(m, struct rte_ether_hdr *)->dst_addr, &opt_sid.id.mac);

	reply_options_len = (int)sizeof(opt_sid) + reply_options.opt_cid_len + reply_options.opt_iana_len + reply_options.opt_rapid_len;
	reply_options_len += (int)(sizeof(dns_opt.opt_code) + sizeof(dns_opt.opt_len) + ntohs(dns_opt.opt_len));

	if (reply_options.pxe_mode != DP_PXE_MODE_NONE)
		reply_options_len += reply_options.opt_boot_file_len;

	if (DP_FAILED(resize_packet(m, reply_options_len - options_len)))
		return DP_ERROR;

	// had to use memcpy() here, because GCC's array-bounds check fails for rte_memcpy (using XMM optimization)
	memcpy(options, &opt_sid, sizeof(opt_sid));
	options += sizeof(opt_sid);
	if (reply_options.opt_cid_len) {
		memcpy(options, (void *)&reply_options.opt_cid, reply_options.opt_cid_len);
		options += reply_options.opt_cid_len;
	}
	if (reply_options.opt_iana_len) {
		memcpy(options, (void *)&reply_options.opt_iana, reply_options.opt_iana_len);
		options += reply_options.opt_iana_len;
	}
	if (reply_options.opt_rapid_len) {
		memcpy(options, &reply_options.opt_rapid, reply_options.opt_rapid_len);
		options += reply_options.opt_rapid_len;
	}

	// Add DNS server option
	memcpy(options, &dns_opt.opt_code, sizeof(dns_opt.opt_code));
	options += sizeof(dns_opt.opt_code);
	memcpy(options, &dns_opt.opt_len, sizeof(dns_opt.opt_len));
	options += sizeof(dns_opt.opt_len);
	memcpy(options, dhcpv6_dns->array, dhcpv6_dns->len);
	options += dhcpv6_dns->len;

	if (reply_options.pxe_mode != DP_PXE_MODE_NONE) {
		memcpy(options, &reply_options.boot_file_url, reply_options.opt_boot_file_len);
		options += reply_options.opt_boot_file_len;
	}

	return reply_options_len;
}

static __rte_always_inline rte_edge_t get_next_index(struct rte_node *node, struct rte_mbuf *m)
{
	struct rte_ether_hdr *req_eth_hdr;
	struct rte_ipv6_hdr *req_ipv6_hdr;
	struct rte_udp_hdr *req_udp_hdr;
	struct dhcpv6_packet *dhcp_pkt;
	int req_options_len = rte_pktmbuf_data_len(m) - (int)DP_DHCPV6_PKT_FIXED_LEN;
	int reply_options_len;
	size_t payload_len;

	if (dp_is_ipv6_zero(&dp_get_in_port(m)->iface.cfg.dhcp_ipv6))
		return DHCPV6_NEXT_DROP;

	// packet length is uint16_t, negative value means it's less than the required length
	if (req_options_len < 0) {
		DPNODE_LOG_WARNING(node, "Invalid DHCPv6 packet length", DP_LOG_VALUE(req_options_len));
		return DHCPV6_NEXT_DROP;
	}

	req_eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
	req_ipv6_hdr = (struct rte_ipv6_hdr *)(req_eth_hdr + 1);
	req_udp_hdr = (struct rte_udp_hdr *)(req_ipv6_hdr + 1);
	dhcp_pkt = (struct dhcpv6_packet *)(req_udp_hdr + 1);

	// switch the packet's direction
	rte_ether_addr_copy(&req_eth_hdr->src_addr, &req_eth_hdr->dst_addr);
	rte_ether_addr_copy(&dp_get_in_port(m)->own_mac, &req_eth_hdr->src_addr);

	dp_set_dst_ipv6(req_ipv6_hdr, dp_get_src_ipv6(req_ipv6_hdr));
	dp_set_src_ipv6(req_ipv6_hdr, own_ip6);
	req_udp_hdr->src_port = htons(DHCPV6_SERVER_PORT);
	req_udp_hdr->dst_port = htons(DHCPV6_CLIENT_PORT);

	// create reply with options
	switch (dhcp_pkt->msg_type) {
	case DHCPV6_SOLICIT:
		dhcp_pkt->msg_type = DHCPV6_ADVERTISE;
		reply_options_len = generate_reply_options(m, dhcp_pkt->options, req_options_len);
		break;
	case DHCPV6_REQUEST:
	case DHCPV6_RELEASE:
		dhcp_pkt->msg_type = DHCPV6_REPLY;
		reply_options_len = generate_reply_options(m, dhcp_pkt->options, req_options_len);
		break;
	case DHCPV6_CONFIRM:
		dhcp_pkt->msg_type = DHCPV6_REPLY;
		reply_options_len = strip_options(m, req_options_len);
		break;
	default:
		return DHCPV6_NEXT_DROP;
	}
	if (DP_FAILED(reply_options_len))
		return DHCPV6_NEXT_DROP;

	payload_len = reply_options_len + DP_DHCPV6_HDR_FIXED_LEN + sizeof(struct rte_udp_hdr);
	if (payload_len > UINT16_MAX)
		return DHCPV6_NEXT_DROP;

	// recompute checksums (offloaded)
	req_ipv6_hdr->payload_len = req_udp_hdr->dgram_len = htons((uint16_t)payload_len);
	req_udp_hdr->dgram_cksum = 0;

	m->ol_flags |= RTE_MBUF_F_TX_IPV6 | RTE_MBUF_F_TX_UDP_CKSUM;
	m->tx_offload = 0;
	m->l2_len = sizeof(struct rte_ether_hdr);
	m->l3_len = sizeof(struct rte_ipv6_hdr);
	m->l4_len = sizeof(struct rte_udp_hdr);

	return next_tx_index[m->port];
}

static uint16_t dhcpv6_node_process(struct rte_graph *graph,
									struct rte_node *node,
									void **objs,
									uint16_t nb_objs)
{
	dp_foreach_graph_packet(graph, node, objs, nb_objs, DP_GRAPH_NO_SPECULATED_NODE, get_next_index);
	return nb_objs;
}
