// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#include "nodes/ipsec_encap_node.h"
#include <rte_common.h>
#include <rte_crypto.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_mbuf.h>
#include "dp_error.h"
#include "dp_ipsec.h"
#include "dp_log.h"
#include "dp_mbuf_dyn.h"
#include "nodes/common_node.h"

DP_NODE_REGISTER_NOINIT(IPSEC_ENCAP, ipsec_encap, DP_NODE_DEFAULT_NEXT_ONLY);

static uint16_t next_tx_index[DP_MAX_PORTS];

int ipsec_encap_node_append_pf_tx(uint16_t port_id, const char *tx_node_name)
{
	return dp_node_append_pf_tx(DP_NODE_GET_SELF(ipsec_encap), next_tx_index, port_id, tx_node_name);
}

// Turn the packet ipip_encap produced into an ESP tunnel-mode one, by inserting the ESP
// header in-between the outer IPv6 header and what it tunnels, and appending the trailer.
// What ends up encrypted is everything from the tunneled packet to the end of the trailer.
static __rte_always_inline int ipsec_encap_packet(struct rte_node *node,
												  struct rte_mbuf *m,
												  struct rte_crypto_op *op)
{
	struct rte_ether_hdr *ether_hdr;
	struct rte_ipv6_hdr *ipv6_hdr;
	struct dp_esp_hdr *esp_hdr;
	struct dp_esp_tail *esp_tail;
	uint8_t *head;
	uint8_t *tail;
	uint64_t seq;
	uint32_t payload_len;
	uint32_t crypt_len;
	uint16_t pad_len;
	uint8_t next_proto;

	payload_len = rte_pktmbuf_pkt_len(m) - DP_IPSEC_OUTER_LEN;
	// the encrypted part has to end on a block boundary, the trailer is a part of it
	pad_len = (DP_IPSEC_BLOCK_SIZE - ((payload_len + sizeof(struct dp_esp_tail)) % DP_IPSEC_BLOCK_SIZE))
			  % DP_IPSEC_BLOCK_SIZE;
	crypt_len = payload_len + pad_len + sizeof(struct dp_esp_tail);

	// Growing the packet first, while the headers are still where they were. Prepending
	// does not move the bytes already in the buffer, so 'tail' stays valid afterwards.
	tail = (uint8_t *)rte_pktmbuf_append(m, pad_len + sizeof(struct dp_esp_tail) + DP_IPSEC_ICV_LEN);
	if (unlikely(!tail)) {
		DPNODE_LOG_WARNING(node, "No space in mbuf for the ESP trailer", DP_LOG_VALUE(payload_len));
		return DP_ERROR;
	}

	head = (uint8_t *)rte_pktmbuf_prepend(m, DP_IPSEC_HDR_LEN);
	if (unlikely(!head)) {
		DPNODE_LOG_WARNING(node, "No space in mbuf for the ESP header", DP_LOG_VALUE(payload_len));
		return DP_ERROR;
	}

	// ESP goes in-between, so the outer header moves to the front of the new space
	memmove(head, head + DP_IPSEC_HDR_LEN, DP_IPSEC_OUTER_LEN);

	ether_hdr = (struct rte_ether_hdr *)head;
	ipv6_hdr = (struct rte_ipv6_hdr *)(ether_hdr + 1);
	esp_hdr = (struct dp_esp_hdr *)(ipv6_hdr + 1);

	// what the outer header used to carry is now what ESP carries
	next_proto = ipv6_hdr->proto;
	ipv6_hdr->proto = IPPROTO_ESP;
	ipv6_hdr->payload_len = htons((uint16_t)(DP_IPSEC_HDR_LEN + crypt_len + DP_IPSEC_ICV_LEN));

	seq = dp_ipsec_next_seq();
	esp_hdr->spi = htonl(DP_IPSEC_SPI);
	esp_hdr->seq = htonl((uint32_t)seq);
	// the sequence number doubles as the nonce, so it cannot repeat under this key
	*(rte_be64_t *)(esp_hdr + 1) = rte_cpu_to_be_64(seq);

	for (uint16_t i = 0; i < pad_len; ++i)
		tail[i] = (uint8_t)(i + 1);  // RFC 4303 wants the padding to count up from one
	esp_tail = (struct dp_esp_tail *)(tail + pad_len);
	esp_tail->pad_len = (uint8_t)pad_len;
	esp_tail->next_proto = next_proto;

	dp_ipsec_prepare_op(op, m, esp_hdr, crypt_len, true);
	return DP_OK;
}

static __rte_always_inline rte_edge_t get_next_index(__rte_unused struct rte_node *node, struct rte_mbuf *m)
{
	struct dp_flow *df = dp_get_flow_ptr(m);

	if (unlikely(dp_get_pkt_mark(m)->flags.crypto_failed))
		return IPSEC_ENCAP_NEXT_DROP;

	return next_tx_index[df->nxt_hop];
}

// Unlike the other nodes, crypto is a burst operation, so the whole burst has to be
// submitted before any of its packets can be forwarded. Only the edge assignment is left
// to dp_foreach_graph_packet(), which is also what keeps graphtrace working here.
static uint16_t ipsec_encap_node_process(struct rte_graph *graph,
										 struct rte_node *node,
										 void **objs,
										 uint16_t nb_objs)
{
	struct rte_crypto_op *ops[RTE_GRAPH_BURST_SIZE];
	struct rte_crypto_op *done[RTE_GRAPH_BURST_SIZE];
	struct rte_mbuf *m;
	uint16_t nb_ops = 0;
	uint16_t nb_done;

	// this is all-or-nothing, it does not allocate a smaller amount
	if (unlikely(rte_crypto_op_bulk_alloc(dp_ipsec_get_op_pool(), RTE_CRYPTO_OP_TYPE_SYMMETRIC,
										  ops, nb_objs) == 0)) {
		DPNODE_LOG_WARNING(node, "Cannot allocate crypto operations", DP_LOG_VALUE(nb_objs));
		for (uint16_t i = 0; i < nb_objs; ++i)
			dp_get_pkt_mark((struct rte_mbuf *)objs[i])->flags.crypto_failed = true;
		dp_foreach_graph_packet(graph, node, objs, nb_objs, DP_GRAPH_NO_SPECULATED_NODE, get_next_index);
		return nb_objs;
	}

	for (uint16_t i = 0; i < nb_objs; ++i) {
		m = (struct rte_mbuf *)objs[i];
		// fail closed: only a completed operation clears this again
		dp_get_pkt_mark(m)->flags.crypto_failed = true;
		if (DP_FAILED(ipsec_encap_packet(node, m, ops[nb_ops])))
			continue;
		++nb_ops;
	}

	if (likely(nb_ops > 0)) {
		rte_memcpy(done, ops, nb_ops * sizeof(*done));
		nb_done = dp_ipsec_process_burst(done, nb_ops);
		for (uint16_t i = 0; i < nb_done; ++i) {
			if (unlikely(done[i]->status != RTE_CRYPTO_OP_STATUS_SUCCESS)) {
				DPNODE_LOG_WARNING(node, "Cannot encrypt packet", DP_LOG_VALUE(done[i]->status));
				continue;
			}
			dp_get_pkt_mark(done[i]->sym->m_src)->flags.crypto_failed = false;
		}
	}

	// freeing via the untouched array, the processed one is in completion order
	for (uint16_t i = 0; i < nb_objs; ++i)
		rte_crypto_op_free(ops[i]);

	dp_foreach_graph_packet(graph, node, objs, nb_objs, DP_GRAPH_NO_SPECULATED_NODE, get_next_index);
	return nb_objs;
}
