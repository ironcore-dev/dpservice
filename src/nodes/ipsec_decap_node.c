// SPDX-FileCopyrightText: 2023 SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

#include <rte_common.h>
#include <rte_crypto.h>
#include <rte_esp.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_ipsec.h>
#include <rte_ipsec_group.h>
#include <rte_mbuf.h>
#include "dp_error.h"
#include "dp_ipsec.h"
#include "dp_log.h"
#include "dp_mbuf_dyn.h"
#include "nodes/common_node.h"

#define NEXT_NODES(NEXT) \
	NEXT(IPSEC_DECAP_NEXT_IPIP_DECAP, "ipip_decap")
DP_NODE_REGISTER_NOINIT(IPSEC_DECAP, ipsec_decap, NEXT_NODES);

// Enough to hold the outer header and the ESP header the SPI is read out of
#define IPSEC_DECAP_MIN_LEN ((uint32_t)(sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv6_hdr) \
									    + sizeof(struct rte_esp_hdr)))

// The inbound Security Association is named by the packet itself: the SPI it carries plus the
// underlay addresses it arrived with. A packet too short to hold an ESP header gets a zeroed
// key, which cannot match, because a stored association always carries this instance's own
// underlay prefix on its local side.
static __rte_always_inline void ipsec_decap_build_key(union rte_ipsec_sad_key *key, struct rte_mbuf *m)
{
	const struct rte_ether_hdr *ether_hdr = rte_pktmbuf_mtod(m, const struct rte_ether_hdr *);
	const struct rte_ipv6_hdr *ipv6_hdr = (const struct rte_ipv6_hdr *)(ether_hdr + 1);
	const struct rte_esp_hdr *esp_hdr = (const struct rte_esp_hdr *)(ipv6_hdr + 1);

	if (unlikely(rte_pktmbuf_pkt_len(m) < IPSEC_DECAP_MIN_LEN)) {
		memset(key, 0, sizeof(*key));
		return;
	}

	dp_ipsec_build_key(key, ntohl(esp_hdr->spi),
					   dp_get_src_ipv6(ipv6_hdr), dp_get_dst_ipv6(ipv6_hdr));
}

// Hand the packet to librte_ipsec, which builds the operation that decrypts everything past the
// ESP header. Transport mode needs to know where the outer header ends, and nothing sets that
// on a packet received from a PF.
static __rte_always_inline int ipsec_decap_prepare(struct rte_mbuf *m,
												   struct rte_crypto_op **op,
												   struct dp_ipsec_sa *sa)
{
	m->l2_len = sizeof(struct rte_ether_hdr);
	m->l3_len = sizeof(struct rte_ipv6_hdr);

	if (unlikely(rte_ipsec_pkt_crypto_prepare(&sa->ipsec_session, &m, op, 1) != 1))
		return DP_ERROR;

	return DP_OK;
}

// librte_ipsec has already taken ESP back out and restored what the outer header used to carry,
// leaving exactly what ipip_encap would have produced on the sending side. What it cannot know
// is dpservice's own view of the packet, which cls could not fill in before it was decrypted.
static __rte_always_inline int ipsec_decap_restore_flow(struct rte_node *node, struct rte_mbuf *m)
{
	const struct rte_ether_hdr *ether_hdr = rte_pktmbuf_mtod(m, const struct rte_ether_hdr *);
	const struct rte_ipv6_hdr *ipv6_hdr = (const struct rte_ipv6_hdr *)(ether_hdr + 1);
	struct dp_flow *df = dp_get_flow_ptr(m);

	switch (ipv6_hdr->proto) {
	case IPPROTO_IPIP:
		df->l3_type = RTE_ETHER_TYPE_IPV4;
		break;
	case IPPROTO_IPV6:
		df->l3_type = RTE_ETHER_TYPE_IPV6;
		break;
	default:
		DPNODE_LOG_WARNING(node, "Invalid tunnel type in ESP trailer", DP_LOG_VALUE(ipv6_hdr->proto));
		return DP_ERROR;
	}
	df->tun_info.proto_id = ipv6_hdr->proto;

	return DP_OK;
}

static __rte_always_inline rte_edge_t get_next_index(__rte_unused struct rte_node *node, struct rte_mbuf *m)
{
	if (unlikely(dp_get_pkt_mark(m)->flags.crypto_failed))
		return IPSEC_DECAP_NEXT_DROP;

	return IPSEC_DECAP_NEXT_IPIP_DECAP;
}

// See ipsec_encap_node_process() for why this node does not simply use
// dp_foreach_graph_packet() for the whole of its work, and for the three places a packet can
// be lost in.
static uint16_t ipsec_decap_node_process(struct rte_graph *graph,
										 struct rte_node *node,
										 void **objs,
										 uint16_t nb_objs)
{
	union rte_ipsec_sad_key keys[RTE_GRAPH_BURST_SIZE];
	const union rte_ipsec_sad_key *keyptrs[RTE_GRAPH_BURST_SIZE];
	struct dp_ipsec_sa *sas[RTE_GRAPH_BURST_SIZE];
	struct rte_crypto_op *ops[RTE_GRAPH_BURST_SIZE];
	struct rte_crypto_op *done[RTE_GRAPH_BURST_SIZE];
	const struct rte_crypto_op *readonly[RTE_GRAPH_BURST_SIZE];
	struct rte_mbuf *grouped[RTE_GRAPH_BURST_SIZE];
	struct rte_ipsec_group groups[RTE_GRAPH_BURST_SIZE];
	struct rte_mbuf *m;
	uint16_t nb_ops = 0;
	uint16_t nb_done;
	uint16_t nb_groups;

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
		keyptrs[i] = &keys[i];
		ipsec_decap_build_key(&keys[i], m);
	}

	dp_ipsec_lookup_sa(keyptrs, sas, nb_objs);

	for (uint16_t i = 0; i < nb_objs; ++i) {
		// Nothing matched this SPI and address pair, so the packet is not for any association
		// we hold and is dropped. Silent on purpose, see ipsec_encap_node_process().
		if (!sas[i])
			continue;
		if (unlikely(DP_FAILED(ipsec_decap_prepare((struct rte_mbuf *)objs[i], &ops[nb_ops], sas[i])))) {
			// nothing has been decrypted yet, so this is the anti-replay window rejecting the
			// sequence number, or a frame too short to be ESP at all
			DPNODE_LOG_WARNING(node, "Cannot accept packet for decryption", DP_LOG_RET(-rte_errno));
			continue;
		}
		++nb_ops;
	}

	if (likely(nb_ops > 0)) {
		rte_memcpy(done, ops, nb_ops * sizeof(*done));
		nb_done = dp_ipsec_process_burst(done, nb_ops);

		// the grouping below only records *that* an operation failed, so the status is reported
		// from here, where it is still at hand
		for (uint16_t i = 0; i < nb_done; ++i) {
			if (unlikely(done[i]->status != RTE_CRYPTO_OP_STATUS_SUCCESS))
				DPNODE_LOG_WARNING(node, "Cannot decrypt packet", DP_LOG_VALUE(done[i]->status));
			// the grouping only reads the operations, but takes them as pointers to const,
			// which C does not convert to on its own
			readonly[i] = done[i];
		}

		// Operations come back in completion order, which is not the order they were submitted
		// in, and librte_ipsec finalizes one association at a time. Both are what this regroups.
		nb_groups = rte_ipsec_pkt_crypto_group(readonly, grouped, groups, nb_done);
		for (uint16_t i = 0; i < nb_groups; ++i) {
			struct rte_ipsec_group *grp = &groups[i];
			uint16_t nb_ok;

			// failures are moved to the end of the group, so everything before this succeeded
			nb_ok = rte_ipsec_pkt_process(grp->id.ptr, grp->m, (uint16_t)grp->cnt);
			for (uint16_t j = 0; j < nb_ok; ++j)
				if (likely(DP_SUCCESS(ipsec_decap_restore_flow(node, grp->m[j]))))
					dp_get_pkt_mark(grp->m[j])->flags.crypto_failed = false;
			for (uint16_t j = nb_ok; j < (uint16_t)grp->cnt; ++j)
				// authentication failures were reported above, with their status; what is left
				// is a malformed trailer or a sequence number repeated inside this very burst
				if (!(grp->m[j]->ol_flags & RTE_MBUF_F_RX_SEC_OFFLOAD_FAILED))
					DPNODE_LOG_WARNING(node, "Cannot finalize decrypted packet");
		}
	}

	// freeing via the untouched array, the processed one is in completion order
	for (uint16_t i = 0; i < nb_objs; ++i)
		rte_crypto_op_free(ops[i]);

	dp_foreach_graph_packet(graph, node, objs, nb_objs, DP_GRAPH_NO_SPECULATED_NODE, get_next_index);
	return nb_objs;
}
