// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#include "monitoring/dp_graphtrace_shared.h"

#include "dp_util.h"

#define PRINT_LAYER(PPOS, BUF, BUFSIZE, FORMAT, ...) do { \
	if (*(PPOS) < (BUFSIZE)) \
		*(PPOS) += snprintf((BUF) + *(PPOS), (BUFSIZE) - *(PPOS), \
					"%s" FORMAT, \
					*(PPOS) ? " / " : "", \
					##__VA_ARGS__); \
} while (0)

static const char *tcp_strflags[256] = {
	"",       "F",      "S",      "FS",      "R",      "FR",      "SR",      "FSR",
	"P",      "FP",     "SP",     "FSP",     "RP",     "FRP",     "SRP",     "FSRP",
	"A",      "FA",     "SA",     "FSA",     "RA",     "FRA",     "SRA",     "FSRA",
	"PA",     "FPA",    "SPA",    "FSPA",    "RPA",    "FRPA",    "SRPA",    "APRSF",
	"U",      "FU",     "SU",     "FSU",     "RU",     "FRU",     "SRU",     "FSRU",
	"PU",     "FPU",    "SPU",    "FSPU",    "RPU",    "FRPU",    "SRPU",    "UPRSF",
	"AU",     "FAU",    "SAU",    "FSAU",    "RAU",    "FRAU",    "SRAU",    "UARSF",
	"PAU",    "FPAU",   "SPAU",   "FSPAU",   "UAPR",   "FRPAU",   "SRPAU",   "FSRPAU",
	"E",      "FE",     "SE",     "FSE",     "RE",     "FRE",     "SRE",     "FSRE",
	"PE",     "FPE",    "SPE",    "FSPE",    "RPE",    "FRPE",    "SRPE",    "EPRSF",
	"AE",     "FAE",    "SAE",    "FSAE",    "RAE",    "FRAE",    "SRAE",    "EARSF",
	"PAE",    "FPAE",   "SPAE",   "FSPAE",   "EAPR",   "FRPAE",   "SRPAE",   "FSRPAE",
	"UE",     "FUE",    "SUE",    "FSUE",    "RUE",    "FRUE",    "SRUE",    "EURSF",
	"PUE",    "FPUE",   "SPUE",   "FSPUE",   "EUPR",   "FRPUE",   "SRPUE",   "FSRPUE",
	"AUE",    "FAUE",   "SAUE",   "FSAUE",   "EUAR",   "FRAUE",   "SRAUE",   "FSRAUE",
	"PAUE",   "FPAUE",  "SPAUE",  "FSPAUE",  "RPAUE",  "FRPAUE",  "SRPAUE",  "FSRPAUE",
	"C",      "FC",     "SC",     "FSC",     "RC",     "FRC",     "SRC",     "FSRC",
	"PC",     "FPC",    "SPC",    "FSPC",    "RPC",    "FRPC",    "SRPC",    "CPRSF",
	"AC",     "FAC",    "SAC",    "FSAC",    "RAC",    "FRAC",    "SRAC",    "CARSF",
	"PAC",    "FPAC",   "SPAC",   "FSPAC",   "CAPR",   "FRPAC",   "SRPAC",   "FSRPAC",
	"UC",     "FUC",    "SUC",    "FSUC",    "RUC",    "FRUC",    "SRUC",    "CURSF",
	"PUC",    "FPUC",   "SPUC",   "FSPUC",   "CUPR",   "FRPUC",   "SRPUC",   "FSRPUC",
	"AUC",    "FAUC",   "SAUC",   "FSAUC",   "CUAR",   "FRAUC",   "SRAUC",   "FSRAUC",
	"PAUC",   "FPAUC",  "SPAUC",  "FSPAUC",  "RPAUC",  "FRPAUC",  "SRPAUC",  "FSRPAUC",
	"EC",     "FEC",    "SEC",    "FSEC",    "REC",    "FREC",    "SREC",    "CERSF",
	"PEC",    "FPEC",   "SPEC",   "FSPEC",   "CEPR",   "FRPEC",   "SRPEC",   "FSRPEC",
	"AEC",    "FAEC",   "SAEC",   "FSAEC",   "CEAR",   "FRAEC",   "SRAEC",   "FSRAEC",
	"PAEC",   "FPAEC",  "SPAEC",  "FSPAEC",  "RPAEC",  "FRPAEC",  "SRPAEC",  "FSRPAEC",
	"UEC",    "FUEC",   "SUEC",   "FSUEC",   "CEUR",   "FRUEC",   "SRUEC",   "FSRUEC",
	"PUEC",   "FPUEC",  "SPUEC",  "FSPUEC",  "RPUEC",  "FRPUEC",  "SRPUEC",  "FSRPUEC",
	"AUEC",   "FAUEC",  "SAUEC",  "FSAUEC",  "RAUEC",  "FRAUEC",  "SRAUEC",  "FSRAUEC",
	"PAUEC",  "FPAUEC", "SPAUEC", "FSPAUEC", "RPAUEC", "FRPAUEC", "SRPAUEC", "FSRPAUEC",
};

static void dp_graphtrace_sprint_ether(void **p_pkt_data, size_t *p_pos, char *buf, size_t bufsize)
{
	struct rte_ether_hdr *ether_hdr = (struct rte_ether_hdr *)*p_pkt_data;

	PRINT_LAYER(p_pos, buf, bufsize,
		RTE_ETHER_ADDR_PRT_FMT " -> " RTE_ETHER_ADDR_PRT_FMT,
		RTE_ETHER_ADDR_BYTES(&ether_hdr->src_addr), RTE_ETHER_ADDR_BYTES(&ether_hdr->dst_addr));

	*p_pkt_data = ether_hdr + 1;
}

static int dp_graphtrace_sprint_ipv4(void **p_pkt_data, size_t *p_pos, char *buf, size_t bufsize)
{
	struct rte_ipv4_hdr *ipv4_hdr = (struct rte_ipv4_hdr *)*p_pkt_data;

	PRINT_LAYER(p_pos, buf, bufsize,
		DP_IPV4_PRINT_FMT " -> " DP_IPV4_PRINT_FMT,
		DP_IPV4_PRINT_BYTES(ipv4_hdr->src_addr), DP_IPV4_PRINT_BYTES(ipv4_hdr->dst_addr));

	*p_pkt_data = ipv4_hdr + 1;
	return ipv4_hdr->next_proto_id;
}

static int dp_graphtrace_sprint_ipv6(void **p_pkt_data, size_t *p_pos, char *buf, size_t bufsize)
{
	struct rte_ipv6_hdr *ipv6_hdr = (struct rte_ipv6_hdr *)*p_pkt_data;

	PRINT_LAYER(p_pos, buf, bufsize,
		DP_IPV6_PRINT_FMT " -> " DP_IPV6_PRINT_FMT,
		DP_IPV6_PRINT_BYTES(ipv6_hdr->src_addr.a), DP_IPV6_PRINT_BYTES(ipv6_hdr->dst_addr.a));

	*p_pkt_data = ipv6_hdr + 1;
	return ipv6_hdr->proto;
}

static void dp_graphtrace_sprint_udp(void **p_pkt_data, size_t *p_pos, char *buf, size_t bufsize)
{
	struct rte_udp_hdr *udp_hdr = (struct rte_udp_hdr *)*p_pkt_data;

	PRINT_LAYER(p_pos, buf, bufsize,
		"UDP %u -> %u len %u",
		ntohs(udp_hdr->src_port), ntohs(udp_hdr->dst_port), ntohs(udp_hdr->dgram_len));

	*p_pkt_data = udp_hdr + 1;
}

static void dp_graphtrace_sprint_tcp(void **p_pkt_data, size_t *p_pos, char *buf, size_t bufsize)
{
	struct rte_tcp_hdr *tcp_hdr = (struct rte_tcp_hdr *)*p_pkt_data;

	PRINT_LAYER(p_pos, buf, bufsize,
		"TCP %u -> %u [%s] seq %u ack %u",
		ntohs(tcp_hdr->src_port), ntohs(tcp_hdr->dst_port),
		tcp_strflags[tcp_hdr->tcp_flags],
		ntohl(tcp_hdr->sent_seq), ntohl(tcp_hdr->recv_ack));

	*p_pkt_data = tcp_hdr + 1;
}

static void dp_graphtrace_sprint_icmp(void **p_pkt_data, size_t *p_pos, char *buf, size_t bufsize)
{
	struct rte_icmp_hdr *icmp_hdr = (struct rte_icmp_hdr *)*p_pkt_data;

	PRINT_LAYER(p_pos, buf, bufsize,
		"ICMP %u-%u id %u seq %u",
		icmp_hdr->icmp_type, icmp_hdr->icmp_code, ntohs(icmp_hdr->icmp_ident), ntohs(icmp_hdr->icmp_seq_nb));

	*p_pkt_data = icmp_hdr + 1;
}

static inline void dp_graphtrace_sprint_l4(int proto, void **p_pkt_data, size_t *p_pos, char *buf, size_t bufsize)
{
	if (proto == IPPROTO_UDP)
		dp_graphtrace_sprint_udp(p_pkt_data, p_pos, buf, bufsize);
	else if (proto == IPPROTO_TCP)
		dp_graphtrace_sprint_tcp(p_pkt_data, p_pos, buf, bufsize);
	else if (proto == IPPROTO_ICMP || proto == IPPROTO_ICMPV6)
		dp_graphtrace_sprint_icmp(p_pkt_data, p_pos, buf, bufsize);
}

void dp_graphtrace_sprint(const struct rte_mbuf *pkt, char *buf, size_t bufsize)
{
	void *pkt_data = rte_pktmbuf_mtod((const struct rte_mbuf *)pkt, void *);
	uint32_t inner_l3_type = pkt->packet_type & RTE_PTYPE_INNER_L3_MASK;
	size_t pos = 0;
	int proto = 0;

	// in case nothing gets printed
	*buf = 0;

	if (pkt->packet_type & RTE_PTYPE_L2_MASK)
		dp_graphtrace_sprint_ether(&pkt_data, &pos, buf, bufsize);

	if (RTE_ETH_IS_IPV4_HDR(pkt->packet_type))
		proto = dp_graphtrace_sprint_ipv4(&pkt_data, &pos, buf, bufsize);
	else if (RTE_ETH_IS_IPV6_HDR(pkt->packet_type))
		proto = dp_graphtrace_sprint_ipv6(&pkt_data, &pos, buf, bufsize);
	else {
		if ((pkt->packet_type & RTE_PTYPE_L4_MASK) == RTE_PTYPE_L4_UDP)
			proto = IPPROTO_UDP;
		else if ((pkt->packet_type & RTE_PTYPE_L4_MASK) == RTE_PTYPE_L4_TCP)
			proto = IPPROTO_TCP;
		else if ((pkt->packet_type & RTE_PTYPE_L4_MASK) == RTE_PTYPE_L4_ICMP)
			proto = IPPROTO_ICMP;
	}

	dp_graphtrace_sprint_l4(proto, &pkt_data, &pos, buf, bufsize);

	// the inner packet is sometimes not classified as a tunneled packet,
	// so need to look at IPPROTO_IPIP in the header too

	if (pkt->packet_type & RTE_PTYPE_INNER_L2_MASK)
		dp_graphtrace_sprint_ether(&pkt_data, &pos, buf, bufsize);

	if (proto != IPPROTO_IPIP && (pkt->packet_type & RTE_PTYPE_TUNNEL_MASK) != RTE_PTYPE_TUNNEL_IP)
		return;

	// there is no direct macro for inner types (no shared bit)
	if (proto == IPPROTO_IPIP
		|| inner_l3_type == RTE_PTYPE_INNER_L3_IPV4
		|| inner_l3_type == RTE_PTYPE_INNER_L3_IPV4_EXT
		|| inner_l3_type == RTE_PTYPE_INNER_L3_IPV4_EXT_UNKNOWN
	) {
		proto = dp_graphtrace_sprint_ipv4(&pkt_data, &pos, buf, bufsize);
	} else if (inner_l3_type == RTE_PTYPE_INNER_L3_IPV6
			|| inner_l3_type == RTE_PTYPE_INNER_L3_IPV6_EXT
			|| inner_l3_type == RTE_PTYPE_INNER_L3_IPV6_EXT_UNKNOWN
	) {
		proto = dp_graphtrace_sprint_ipv6(&pkt_data, &pos, buf, bufsize);
	} else {
		if ((pkt->packet_type & RTE_PTYPE_INNER_L4_MASK) == RTE_PTYPE_INNER_L4_UDP)
			proto = IPPROTO_UDP;
		else if ((pkt->packet_type & RTE_PTYPE_INNER_L4_MASK) == RTE_PTYPE_INNER_L4_TCP)
			proto = IPPROTO_TCP;
		else if ((pkt->packet_type & RTE_PTYPE_INNER_L4_MASK) == RTE_PTYPE_INNER_L4_ICMP)
			proto = IPPROTO_ICMP;
	}

	dp_graphtrace_sprint_l4(proto, &pkt_data, &pos, buf, bufsize);
}
